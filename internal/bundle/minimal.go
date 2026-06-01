package bundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/depx/internal/osv"
)

// BuildMinimalOSV writes a small offline bundle for dev/test builds.
func BuildMinimalOSV(outPath string, builtAt time.Time) error {
	if builtAt.IsZero() {
		builtAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	}
	tmp, err := os.MkdirTemp("", "depx-osv-bundle-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	modified := builtAt.Add(-2 * time.Hour)
	idx := osv.NewEmptyMaliciousIndex()
	idx.AddListing("npm", "evil-pkg", "MAL-2026-TEST1", "Malicious code in evil-pkg (npm)", true, nil, builtAt, modified)
	idx.AddListing("PyPI", "apkeep", "MAL-2026-3431", "Malicious code in apkeep (PyPI)", true, nil, builtAt, modified)

	compiledPath := osv.CompiledCachePath(tmp, "compiled")
	if err := osv.SaveCompiledIndex(compiledPath, 2, idx); err != nil {
		return err
	}

	entries := []osv.IndexEntry{
		{ID: "MAL-2026-TEST1", Ecosystem: "npm", Modified: modified},
		{ID: "MAL-2026-3431", Ecosystem: "PyPI", Modified: modified},
	}
	if err := writeMinimalVulnBlob(tmp, "MAL-2026-TEST1", &osv.Vulnerability{
		ID:      "MAL-2026-TEST1",
		Summary: "Malicious code in evil-pkg (npm)",
		Affected: []osv.Affected{{
			Package: &osv.Package{Ecosystem: "npm", Name: "evil-pkg"},
		}},
	}); err != nil {
		return err
	}
	if err := writeMinimalVulnBlob(tmp, "MAL-2026-3431", &osv.Vulnerability{
		ID:      "MAL-2026-3431",
		Summary: "Malicious code in apkeep (PyPI)",
		Affected: []osv.Affected{{
			Package: &osv.Package{Ecosystem: "PyPI", Name: "apkeep"},
		}},
	}); err != nil {
		return err
	}
	if err := writeFeedIndexCache(tmp, entries); err != nil {
		return err
	}

	m := &cacheManifest{
		SchemaVersion: 1,
		Source:        "osv",
		Catalog: cacheCatalogState{
			Fingerprint:    "minimal-osv",
			EntryCount:     2,
			LatestModified: modified,
			FetchedAt:      builtAt,
		},
		Entries: map[string]cacheEntry{
			"MAL-2026-TEST1": {Ecosystem: "npm", Modified: modified, Blob: "vulns/MAL-2026-TEST1.json", Status: "ready", FetchedAt: builtAt},
			"MAL-2026-3431":  {Ecosystem: "PyPI", Modified: modified, Blob: "vulns/MAL-2026-3431.json", Status: "ready", FetchedAt: builtAt},
		},
		Compiled: cacheCompiledState{
			Path:         "mal/compiled.json",
			EntryCount:   2,
			PackageCount: idx.PackageCount(),
			BuiltAt:      builtAt,
		},
		Sync: cacheSyncState{State: "idle", LastSuccess: builtAt},
	}
	if err := saveCacheManifest(tmp, m); err != nil {
		return err
	}

	return Pack(tmp, "osv", Meta{Source: "osv", BuiltAt: builtAt, EntryCount: 2, PackageCount: idx.PackageCount()}, outPath)
}

// BuildMinimalPD writes a small offline bundle for dev/test builds.
func BuildMinimalPD(outPath string, builtAt time.Time) error {
	if builtAt.IsZero() {
		builtAt = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	}
	tmp, err := os.MkdirTemp("", "depx-pd-bundle-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	modified := builtAt.Add(-2 * time.Hour)
	idx := osv.NewEmptyMaliciousIndex()
	idx.AddListing("npm", "evil-pkg", "GHSCAN-MAL-1", "Malicious code in evil-pkg (npm)", true, nil, builtAt, modified)
	idx.AddListing("PyPI", "apkeep", "GHSCAN-MAL-APKEEP", "Malicious code in apkeep (PyPI)", true, nil, builtAt, modified)

	compiledPath := osv.CompiledCachePath(tmp, "pd_compiled")
	if err := osv.SaveCompiledIndex(compiledPath, 2, idx); err != nil {
		return err
	}

	m := &cacheManifest{
		SchemaVersion: 1,
		Source:        "pd",
		Compiled: cacheCompiledState{
			Path:         "mal/pd_compiled.json",
			EntryCount:   2,
			PackageCount: idx.PackageCount(),
			BuiltAt:      builtAt,
		},
		Sync: cacheSyncState{State: "idle", LastSuccess: builtAt},
	}
	if err := saveCacheManifest(tmp, m); err != nil {
		return err
	}

	return Pack(tmp, "pd", Meta{Source: "pd", BuiltAt: builtAt, EntryCount: 2, PackageCount: idx.PackageCount()}, outPath)
}

func writeFeedIndexCache(cacheDir string, entries []osv.IndexEntry) error {
	path := filepath.Join(cacheDir, "feed", "index.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		FetchedAt time.Time        `json:"fetched_at"`
		Entries   []osv.IndexEntry `json:"entries"`
	}{
		FetchedAt: time.Now().UTC(),
		Entries:   entries,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}

// BuildFromCache packs an existing sync cache directory into a release bundle.
func BuildFromCache(cacheDir, source, outPath string) error {
	m, err := loadCacheManifest(cacheDir, source)
	if err != nil {
		return err
	}
	if m.Compiled.PackageCount == 0 {
		return fmt.Errorf("cache for %s has no compiled index", source)
	}
	builtAt := m.Compiled.BuiltAt
	if builtAt.IsZero() {
		builtAt = time.Now().UTC()
	}
	return Pack(cacheDir, source, Meta{
		Source:       source,
		BuiltAt:      builtAt,
		EntryCount:   m.Catalog.EntryCount,
		PackageCount: m.Compiled.PackageCount,
	}, outPath)
}

func writeMinimalVulnBlob(cacheDir, id string, vuln *osv.Vulnerability) error {
	path := filepath.Join(cacheDir, "vulns", id+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		FetchedAt time.Time          `json:"fetched_at"`
		Record    *osv.Vulnerability `json:"record"`
	}{
		FetchedAt: time.Now().UTC(),
		Record:    vuln,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}
