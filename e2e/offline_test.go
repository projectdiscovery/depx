package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2EOfflineAfterFirstSync verifies the first run builds a local index from
// the inventory source and subsequent lookups are served from that local cache.
func TestE2EOfflineAfterFirstSync(t *testing.T) {
	srcSrv := mockSourceServer(t)
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath, sourceEnv(srcSrv)...)

	out, code := r.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("first-run search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep from synced index: %s", out)
	}

	out, code = r.run("-j", "search", "evil-pkg")
	if code != 0 {
		t.Fatalf("evil-pkg search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "evil-pkg") {
		t.Fatalf("expected evil-pkg from synced index: %s", out)
	}

	m := readSyncManifest(t, cacheDir, "inventory")
	if m.Compiled.PackageCount == 0 {
		t.Fatal("expected compiled index after sync")
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "mal", "compiled.json")); err != nil {
		t.Fatalf("missing compiled index after sync: %v", err)
	}

	// Close the source: the local index must keep answering.
	srcSrv.Close()
	out, code = r.run("-j", "search", "apkeep")
	if code != 0 {
		t.Fatalf("offline search exit %d: %s", code, out)
	}
	if !strings.Contains(out, "apkeep") {
		t.Fatalf("expected apkeep from offline index: %s", out)
	}
}
