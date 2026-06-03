package sync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/depx/internal/osv"
)

func TestIndexSyncProgressUsesMaliciousCatalogCount(t *testing.T) {
	cacheDir := t.TempDir()
	vulnDir := filepath.Join(cacheDir, osvBlobRel)
	if err := os.MkdirAll(vulnDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"MAL-1", "MAL-2", "MAL-3"} {
		if err := os.WriteFile(filepath.Join(vulnDir, id+".json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := newManifest("osv")
	m.Catalog.MaliciousCount = 10
	if err := saveManifest(cacheDir, m); err != nil {
		t.Fatal(err)
	}

	loaded, total := indexSyncProgress(cacheDir)
	if loaded != 3 {
		t.Fatalf("loaded = %d, want 3", loaded)
	}
	if total != 10 {
		t.Fatalf("total = %d, want 10", total)
	}
}

func TestFormatIndexDownloadProgressWithTotal(t *testing.T) {
	msg := osv.FormatIndexDownloadProgress(158600, 226500)
	if msg != "Downloading malicious package index… 70% (158.6k/226.5k advisories)" {
		t.Fatalf("unexpected message: %q", msg)
	}
}
