package bundle

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSeedIfNeededColdCache(t *testing.T) {
	cacheDir := t.TempDir()
	seeded, err := SeedIfNeeded(cacheDir, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if !seeded {
		t.Fatal("expected embedded seed on cold cache")
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "mal", "compiled.json")); err != nil {
		t.Fatalf("missing compiled index: %v", err)
	}

	again, err := SeedIfNeeded(cacheDir, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if again {
		t.Fatal("expected no re-seed when cache is current")
	}
}

func TestSeedIfNeededColdCachePD(t *testing.T) {
	cacheDir := t.TempDir()
	seeded, err := SeedIfNeeded(cacheDir, "pd")
	if err != nil {
		t.Fatal(err)
	}
	if !seeded {
		t.Fatal("expected embedded pd seed on cold cache")
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "mal", "pd_compiled.json")); err != nil {
		t.Fatalf("missing pd compiled index: %v", err)
	}
	m, err := loadCacheManifest(cacheDir, "pd")
	if err != nil {
		t.Fatal(err)
	}
	if m.Seed == nil || m.Seed.Source != "embedded" {
		t.Fatalf("expected seed.source=embedded, got %+v", m.Seed)
	}
}

func TestEmbeddedMetaBothSources(t *testing.T) {
	for _, src := range []string{"osv", "pd"} {
		meta, ok, err := EmbeddedMeta(src)
		if err != nil {
			t.Fatalf("%s EmbeddedMeta: %v", src, err)
		}
		if !ok {
			t.Fatalf("%s: no embedded bundle", src)
		}
		if meta.Source != src {
			t.Fatalf("%s meta source = %q", src, meta.Source)
		}
		if meta.BuiltAt.IsZero() {
			t.Fatalf("%s: built_at is zero", src)
		}
		if meta.PackageCount == 0 {
			t.Fatalf("%s: package_count is zero", src)
		}
	}
}

func TestSeedIfNeededDisabled(t *testing.T) {
	t.Setenv("DEPX_DISABLE_EMBEDDED_SEED", "1")
	cacheDir := t.TempDir()
	seeded, err := SeedIfNeeded(cacheDir, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if seeded {
		t.Fatal("expected seed disabled")
	}
}

func TestSeedIfNeededReSeedsWhenEmbeddedNewer(t *testing.T) {
	cacheDir := t.TempDir()
	if _, err := SeedIfNeeded(cacheDir, "osv"); err != nil {
		t.Fatal(err)
	}

	embedded, ok, err := EmbeddedMeta("osv")
	if err != nil || !ok {
		t.Fatalf("embedded meta: ok=%v err=%v", ok, err)
	}

	m, err := loadCacheManifest(cacheDir, "osv")
	if err != nil {
		t.Fatal(err)
	}
	m.Compiled.BuiltAt = embedded.BuiltAt.Add(-48 * time.Hour)
	if err := saveCacheManifest(cacheDir, m); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(cacheDir, "mal", "compiled.json"))

	seeded, err := SeedIfNeeded(cacheDir, "osv")
	if err != nil {
		t.Fatal(err)
	}
	if !seeded {
		t.Fatal("expected re-seed when user cache is older than embedded baseline")
	}
}
