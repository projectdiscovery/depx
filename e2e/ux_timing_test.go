package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type uxScenario struct {
	label string
	args  []string
}

func TestE2EUXTimingFreshVsWarm(t *testing.T) {
	osvSrv := mockOSVServer(t)
	osvURL := osvSrv.URL + "/v1"
	modifiedURL := strings.TrimSuffix(osvURL, "/v1") + "/modified_id.csv"
	cleanProject := filepath.Join("..", "testdata", "fixtures", "clean-project")

	scenarios := []uxScenario{
		{label: "dashboard (default)", args: nil},
		{label: "feed", args: []string{"feed"}},
		{label: "feed --list", args: []string{"feed", "--list"}},
		{label: "feed -j -n 3", args: []string{"feed", "-j", "-n", "3"}},
		{label: "feed --since 24h", args: []string{"feed", "--since", "24h"}},
		{label: "search apkeep", args: []string{"search", "apkeep"}},
		{label: "search apkeep --list", args: []string{"search", "apkeep", "--list"}},
		{label: "search apkeep -j", args: []string{"search", "apkeep", "-j"}},
		{label: "audit clean-project", args: []string{"audit", cleanProject}},
		{label: "audit -j clean-project", args: []string{"audit", "-j", cleanProject}},
		{label: "check apkeep", args: []string{"check", "apkeep"}},
		{label: "check -j apkeep", args: []string{"-j", "apkeep"}},
		{label: "version", args: []string{"version"}},
	}

	env := []string{
		"DEPX_INTEL_SOURCE=osv",
		"DEPX_OSV_URL=" + osvURL,
		"DEPX_MODIFIED_INDEX_URL=" + modifiedURL,
	}

	runMatrix := func(t *testing.T, title string, cacheDir string) map[string]time.Duration {
		t.Helper()
		cfgPath := writeTestConfig(t, cacheDir, "")
		r := newE2ERunner(t, cfgPath, env...)
		out := make(map[string]time.Duration, len(scenarios))
		t.Logf("\n=== %s (cache: %s) ===", title, cacheDir)
		t.Logf("%-28s %8s %5s  notes", "command", "time", "exit")
		t.Logf("%-28s %8s %5s  %s", "--------", "----", "----", "-----")
		for _, sc := range scenarios {
			start := time.Now()
			_, code := r.run(sc.args...)
			elapsed := time.Since(start)
			out[sc.label] = elapsed
			note := ""
			if sc.label == "search apkeep" && title == "fresh user" {
				note = "triggers index sync"
			}
			t.Logf("%-28s %8s %5d  %s", sc.label, elapsed.Round(time.Millisecond), code, note)
		}
		return out
	}

	freshCache := t.TempDir()
	fresh := runMatrix(t, "fresh user", freshCache)

	warmCache := freshCache
	warm := runMatrix(t, "existing user (warm cache)", warmCache)

	t.Logf("\n=== delta (warm − fresh) ===")
	t.Logf("%-28s %8s", "command", "saved")
	for _, sc := range scenarios {
		delta := fresh[sc.label] - warm[sc.label]
		t.Logf("%-28s %8s", sc.label, delta.Round(time.Millisecond))
	}

	// Sanity: warm search/audit should not regress badly vs fresh after sync.
	if warm["search apkeep"] > fresh["search apkeep"]*3 && fresh["search apkeep"] > 100*time.Millisecond {
		t.Fatalf("warm search unexpectedly slower than fresh: fresh=%s warm=%s", fresh["search apkeep"], warm["search apkeep"])
	}
}

// TestE2EUXTimingLiveOptional runs against real OSV when DEPX_UX_LIVE=1.
func TestE2EUXTimingLiveOptional(t *testing.T) {
	if os.Getenv("DEPX_UX_LIVE") != "1" {
		t.Skip("set DEPX_UX_LIVE=1 to benchmark real OSV (slow on cold cache)")
	}
	for _, key := range []string{"DEPX_OSV_URL", "DEPX_MODIFIED_INDEX_URL"} {
		if os.Getenv(key) != "" {
			t.Skipf("unset %s for live UX bench", key)
		}
	}

	scenarios := []uxScenario{
		{label: "dashboard", args: nil},
		{label: "feed", args: []string{"feed"}},
		{label: "feed --list", args: []string{"feed", "--list"}},
		{label: "search apk", args: []string{"search", "apk"}},
		{label: "search apk --list", args: []string{"search", "apk", "--list"}},
	}

	freshCache := t.TempDir()
	warmCache := t.TempDir()
	if v := os.Getenv("DEPX_UX_WARM_CACHE"); v != "" {
		warmCache = v
	}

	runLive := func(t *testing.T, title, cacheDir string, firstSearch bool) {
		t.Helper()
		cfgPath := writeTestConfig(t, cacheDir, "")
		r := newE2ERunner(t, cfgPath)
		t.Logf("\n=== LIVE %s (%s) ===", title, cacheDir)
		if firstSearch {
			start := time.Now()
			out, code := r.run("search", "apk")
			t.Logf("%-28s %8s exit=%d", "search apk (index build)", time.Since(start).Round(time.Second), code)
			if code != 0 {
				t.Fatalf("live search failed: %s", trimForLog(out))
			}
		}
		for _, sc := range scenarios {
			if firstSearch && sc.label == "search apk" {
				continue
			}
			start := time.Now()
			_, code := r.run(sc.args...)
			t.Logf("%-28s %8s exit=%d", sc.label, time.Since(start).Round(time.Millisecond), code)
		}
	}

	runLive(t, "fresh user", freshCache, true)
	if warmCache == freshCache {
		runLive(t, "existing user", warmCache, false)
	} else {
		runLive(t, "existing user (prebuilt cache)", warmCache, false)
	}
}
