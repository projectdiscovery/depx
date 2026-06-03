package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2EOfflineSyncFirstRun(t *testing.T) {
	osvSrv := mockOSVServer(t)
	osvURL := osvSrv.URL + "/v1"
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath,
		"DEPX_INTEL_SOURCE=osv",
		"DEPX_OSV_URL="+osvURL,
		"DEPX_MODIFIED_INDEX_URL="+strings.TrimSuffix(osvURL, "/v1")+"/modified_id.csv",
	)

	out, code := r.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("offline search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep from synced index: %s", out)
	}

	out, code = r.run("-j", "search", "evil-pkg")
	if code != 0 {
		t.Fatalf("offline evil-pkg search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "evil-pkg") {
		t.Fatalf("expected evil-pkg from synced index: %s", out)
	}

	m := readSyncManifest(t, cacheDir, "osv")
	if m.Compiled.PackageCount == 0 {
		t.Fatal("expected compiled index after sync")
	}
}

func TestE2EOfflinePD(t *testing.T) {
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath,
		"DEPX_INTEL_SOURCE=pd",
		"DEPX_PD_API_TOKEN=offline-test-token",
		"DEPX_PD_API_URL="+mockPDServer(t).URL,
	)

	out, code := r.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("offline pd search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep from synced pd index: %s", out)
	}
	if !strings.Contains(out, "GHSCAN-MAL-APKEEP") {
		t.Fatalf("expected PD advisory id in search: %s", out)
	}

	out, code = r.run("-j", "search", "evil-pkg")
	if code != 0 {
		t.Fatalf("offline pd evil-pkg search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "evil-pkg") {
		t.Fatalf("expected evil-pkg from synced pd index: %s", out)
	}
	if !strings.Contains(out, "GHSCAN-MAL-1") {
		t.Fatalf("expected PD advisory id for evil-pkg: %s", out)
	}

	if _, err := os.Stat(filepath.Join(cacheDir, "mal", "pd_compiled.json")); err != nil {
		t.Fatalf("missing pd compiled index after sync: %v", err)
	}

	seedPath := filepath.Join(cacheDir, "sync", "pd", "manifest.json")
	data, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Compiled struct {
			PackageCount int `json:"package_count"`
		} `json:"compiled"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Compiled.PackageCount == 0 {
		t.Fatal("expected pd compiled package_count after sync")
	}
}
