package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type syncManifest struct {
	Source   string `json:"source"`
	Sync     struct {
		State       string    `json:"state"`
		LastSuccess time.Time `json:"last_success"`
		Pending     int       `json:"pending"`
	} `json:"sync"`
	Catalog struct {
		Fingerprint string `json:"fingerprint"`
		EntryCount  int    `json:"entry_count"`
	} `json:"catalog"`
	Compiled struct {
		PackageCount int       `json:"package_count"`
		BuiltAt      time.Time `json:"built_at"`
	} `json:"compiled"`
	Entries map[string]struct {
		Status string `json:"status"`
	} `json:"entries"`
}

func readSyncManifest(t *testing.T, cacheDir, source string) syncManifest {
	t.Helper()
	path := filepath.Join(cacheDir, "sync", source, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest %s: %v", path, err)
	}
	var m syncManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m
}

func (r *e2eRunner) runCombined(args ...string) (combined string, exit int) {
	r.t.Helper()
	return r.runCombinedWithStdin("", args...)
}

func (r *e2eRunner) runCombinedWithStdin(stdin string, args ...string) (combined string, exit int) {
	r.t.Helper()
	base := []string{"--disable-update-check", "--config", r.cfgPath}
	cmd := exec.Command(r.bin, append(base, args...)...)
	cmd.Env = append(os.Environ(), r.env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	} else {
		cmd.Stdin = devNullStdin(r.t)
	}
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	exit = 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			r.t.Fatalf("exec %v: %v", args, err)
		}
	}
	return outBuf.String() + errBuf.String(), exit
}

func TestE2ESyncOSV(t *testing.T) {
	osvSrv := mockOSVServer(t)
	osvURL := osvSrv.URL + "/v1"
	modifiedURL := strings.TrimSuffix(osvURL, "/v1") + "/modified_id.csv"

	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath,
		"DEPX_DISABLE_EMBEDDED_SEED=1",
		"DEPX_INTEL_SOURCE=osv",
		"DEPX_OSV_URL="+osvURL,
		"DEPX_MODIFIED_INDEX_URL="+modifiedURL,
	)

	out, code := r.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("cold search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep in search results: %s", out)
	}

	m := readSyncManifest(t, cacheDir, "osv")
	if m.Source != "osv" {
		t.Fatalf("manifest source = %q", m.Source)
	}
	if m.Sync.State != "idle" {
		t.Fatalf("sync state = %q, want idle", m.Sync.State)
	}
	if m.Sync.LastSuccess.IsZero() {
		t.Fatal("expected last_success after cold sync")
	}
	if m.Catalog.Fingerprint == "" {
		t.Fatal("expected catalog fingerprint")
	}
	if m.Catalog.EntryCount < 2 {
		t.Fatalf("catalog entry_count = %d, want >= 2", m.Catalog.EntryCount)
	}
	if m.Compiled.PackageCount == 0 {
		t.Fatal("compiled package_count is 0")
	}
	for id, e := range m.Entries {
		if e.Status != "ready" {
			t.Fatalf("entry %s status = %q, want ready", id, e.Status)
		}
	}

	for _, path := range []string{
		filepath.Join(cacheDir, "mal", "compiled.json"),
		filepath.Join(cacheDir, "vulns", "MAL-2026-TEST1.json"),
		filepath.Join(cacheDir, "feed", "index.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing sync artifact %s: %v", path, err)
		}
	}

	out, code = r.run("-j", "search", "evil")
	if code != 0 {
		t.Fatalf("warm search exit %d: %s", code, out)
	}
	m2 := readSyncManifest(t, cacheDir, "osv")
	if m2.Compiled.BuiltAt.Before(m.Compiled.BuiltAt) {
		t.Fatal("compiled index regressed on warm run")
	}
}

func TestE2ESyncOSVDelta(t *testing.T) {
	recent := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	catalog := fmt.Sprintf("%s,npm/MAL-2026-TEST1\n", recent)

	mux := http.NewServeMux()
	mux.HandleFunc("/modified_id.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(catalog))
	})
	registerOSVAPIRoutes(mux)
	mux.HandleFunc("/v1/vulns/MAL-2026-TEST3", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"MAL-2026-TEST3","summary":"Malicious code in delta-pkg (npm)","affected":[{"package":{"name":"delta-pkg","ecosystem":"npm"}}]}`))
	})
	osvSrv := httptest.NewServer(mux)
	defer osvSrv.Close()

	osvURL := osvSrv.URL + "/v1"
	modifiedURL := osvSrv.URL + "/modified_id.csv"

	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath,
		"DEPX_DISABLE_EMBEDDED_SEED=1",
		"DEPX_INTEL_SOURCE=osv",
		"DEPX_OSV_URL="+osvURL,
		"DEPX_MODIFIED_INDEX_URL="+modifiedURL,
	)

	_, code := r.run("-j", "search", "evil")
	if code != 0 {
		t.Fatalf("initial sync exit %d", code)
	}
	m1 := readSyncManifest(t, cacheDir, "osv")
	if len(m1.Entries) != 1 {
		t.Fatalf("initial entries = %d, want 1", len(m1.Entries))
	}

	catalog = fmt.Sprintf("%s,npm/MAL-2026-TEST1\n%s,npm/MAL-2026-TEST3\n", recent, recent)
	if err := os.Remove(filepath.Join(cacheDir, "mal", "compiled.json")); err != nil {
		t.Fatalf("remove compiled index: %v", err)
	}
	_, code = r.run("-j", "search", "delta")
	if code != 0 {
		t.Fatalf("delta sync exit %d", code)
	}
	m2 := readSyncManifest(t, cacheDir, "osv")
	if len(m2.Entries) != 2 {
		t.Fatalf("entries after delta = %d, want 2", len(m2.Entries))
	}
	if m2.Entries["MAL-2026-TEST3"].Status != "ready" {
		t.Fatalf("MAL-2026-TEST3 status = %q, want ready", m2.Entries["MAL-2026-TEST3"].Status)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "vulns", "MAL-2026-TEST3.json")); err != nil {
		t.Fatalf("missing delta vuln blob: %v", err)
	}

	out, code := r.run("-j", "search", "delta-pkg")
	if code != 0 {
		t.Fatalf("search delta-pkg exit %d: %s", code, out)
	}
	if !strings.Contains(out, "delta-pkg") {
		t.Fatalf("expected delta-pkg in search: %s", out)
	}
}

func TestE2ESyncPD(t *testing.T) {
	pdSrv := mockPDServer(t)
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath,
		"DEPX_INTEL_SOURCE=pd",
		"DEPX_PD_API_TOKEN=test-token",
		"DEPX_PD_API_URL="+pdSrv.URL,
	)

	out, code := r.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("cold search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep in search results: %s", out)
	}

	m := readSyncManifest(t, cacheDir, "pd")
	if m.Source != "pd" {
		t.Fatalf("manifest source = %q", m.Source)
	}
	if m.Sync.State != "idle" {
		t.Fatalf("sync state = %q, want idle", m.Sync.State)
	}
	if m.Sync.LastSuccess.IsZero() {
		t.Fatal("expected last_success after cold sync")
	}
	if m.Compiled.PackageCount < 2 {
		t.Fatalf("compiled package_count = %d, want >= 2", m.Compiled.PackageCount)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "mal", "pd_compiled.json")); err != nil {
		t.Fatalf("missing pd compiled index: %v", err)
	}

	out, code = r.run("-j", "search", "evil")
	if code != 0 {
		t.Fatalf("warm search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "evil-pkg") {
		t.Fatalf("expected evil-pkg on warm search: %s", out)
	}
}

func TestE2ESyncUserVisibleVerbose(t *testing.T) {
	osvSrv := mockOSVServer(t)
	osvURL := osvSrv.URL + "/v1"
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath,
		"DEPX_DISABLE_EMBEDDED_SEED=1",
		"DEPX_INTEL_SOURCE=osv",
		"DEPX_OSV_URL="+osvURL,
		"DEPX_MODIFIED_INDEX_URL="+strings.TrimSuffix(osvURL, "/v1")+"/modified_id.csv",
	)

	// Populate sync manifest before verbose status is shown (status prints in pre-run).
	if _, code := r.run("-j", "search", "apkeep"); code != 0 {
		t.Fatalf("warm-up search exit %d", code)
	}

	combined, code := r.runCombined("-v", "-n", "1")
	if code != 0 {
		t.Fatalf("verbose feed exit %d: %s", code, combined)
	}
	if !strings.Contains(combined, "index osv:") {
		t.Fatalf("expected verbose index status on stderr, got: %s", trimForLog(combined))
	}

	freshCache := t.TempDir()
	freshCfg := writeTestConfig(t, freshCache, "")
	fresh := newE2ERunner(t, freshCfg,
		"DEPX_DISABLE_EMBEDDED_SEED=1",
		"DEPX_INTEL_SOURCE=osv",
		"DEPX_OSV_URL="+osvURL,
		"DEPX_MODIFIED_INDEX_URL="+strings.TrimSuffix(osvURL, "/v1")+"/modified_id.csv",
	)
	cleanProject := filepath.Join("..", "testdata", "fixtures", "clean-project")
	combined, code = fresh.runCombined("-v", "audit", cleanProject)
	if code != 0 {
		t.Fatalf("verbose audit exit %d: %s", code, combined)
	}
	if !strings.Contains(combined, "Malicious package index ready") {
		t.Fatalf("expected audit index-ready progress, got: %s", trimForLog(combined))
	}
}
