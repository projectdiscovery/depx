package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2EOfflineEmbeddedFirstRun(t *testing.T) {
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath,
		"DEPX_INTEL_SOURCE=osv",
		"DEPX_OSV_URL=http://127.0.0.1:1/v1",
		"DEPX_MODIFIED_INDEX_URL=http://127.0.0.1:1/modified_id.csv",
	)

	out, code := r.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("offline search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep from embedded bundle: %s", out)
	}

	out, code = r.run("-j", "search", "evil-pkg")
	if code != 0 {
		t.Fatalf("offline evil-pkg search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "evil-pkg") {
		t.Fatalf("expected evil-pkg from embedded bundle: %s", out)
	}

	m := readSyncManifest(t, cacheDir, "osv")
	if m.Compiled.PackageCount == 0 {
		t.Fatal("expected compiled index after embedded seed")
	}
	seedPath := filepath.Join(cacheDir, "sync", "osv", "manifest.json")
	data, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Seed *struct {
			Source string `json:"source"`
		} `json:"seed"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Seed == nil || raw.Seed.Source != "embedded" {
		t.Fatalf("expected seed.source=embedded, got %+v", raw.Seed)
	}
}

func TestE2EOfflineEmbeddedPD(t *testing.T) {
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath,
		"DEPX_INTEL_SOURCE=pd",
		"DEPX_PD_API_TOKEN=offline-test-token",
		"DEPX_PD_API_URL=http://127.0.0.1:1",
	)

	out, code := r.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("offline pd search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep from embedded pd bundle: %s", out)
	}
	if !strings.Contains(out, "GHSCAN-MAL-APKEEP") {
		t.Fatalf("expected PD advisory id in search: %s", out)
	}

	out, code = r.run("-j", "search", "evil-pkg")
	if code != 0 {
		t.Fatalf("offline pd evil-pkg search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "evil-pkg") {
		t.Fatalf("expected evil-pkg from embedded pd bundle: %s", out)
	}
	if !strings.Contains(out, "GHSCAN-MAL-1") {
		t.Fatalf("expected PD advisory id for evil-pkg: %s", out)
	}

	if _, err := os.Stat(filepath.Join(cacheDir, "mal", "pd_compiled.json")); err != nil {
		t.Fatalf("missing pd compiled index after seed: %v", err)
	}

	seedPath := filepath.Join(cacheDir, "sync", "pd", "manifest.json")
	data, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Seed *struct {
			Source string `json:"source"`
		} `json:"seed"`
		Compiled struct {
			PackageCount int `json:"package_count"`
		} `json:"compiled"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Seed == nil || raw.Seed.Source != "embedded" {
		t.Fatalf("expected pd seed.source=embedded, got %+v", raw.Seed)
	}
	if raw.Compiled.PackageCount == 0 {
		t.Fatal("expected pd compiled package_count after embedded seed")
	}
}
