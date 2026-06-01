package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type cacheManifest struct {
	SchemaVersion int                       `json:"schema_version"`
	Source        string                    `json:"source"`
	Catalog       cacheCatalogState         `json:"catalog"`
	Entries       map[string]cacheEntry     `json:"entries"`
	Compiled      cacheCompiledState        `json:"compiled"`
	Sync          cacheSyncState            `json:"sync"`
	Seed          *cacheSeedState           `json:"seed,omitempty"`
}

type cacheCatalogState struct {
	Fingerprint    string    `json:"fingerprint"`
	EntryCount     int       `json:"entry_count"`
	LatestModified time.Time `json:"latest_modified,omitempty"`
	FetchedAt      time.Time `json:"fetched_at,omitempty"`
}

type cacheEntry struct {
	Ecosystem string    `json:"ecosystem"`
	Modified  time.Time `json:"modified"`
	Blob      string    `json:"blob"`
	Status    string    `json:"status"`
	FetchedAt time.Time `json:"fetched_at,omitempty"`
}

type cacheCompiledState struct {
	Path         string    `json:"path"`
	EntryCount   int       `json:"entry_count"`
	PackageCount int       `json:"package_count"`
	BuiltAt      time.Time `json:"built_at,omitempty"`
}

type cacheSyncState struct {
	State       string    `json:"state"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	Pending     int       `json:"pending"`
	LastError   string    `json:"last_error,omitempty"`
}

type cacheSeedState struct {
	Source          string    `json:"source"`
	EmbeddedBuiltAt time.Time `json:"embedded_built_at,omitempty"`
	EmbeddedVersion int       `json:"embedded_version,omitempty"`
	LastSeedAt      time.Time `json:"last_seed_at,omitempty"`
}

func manifestPath(cacheDir, source string) string {
	return filepath.Join(cacheDir, "sync", source, "manifest.json")
}

func loadCacheManifest(cacheDir, source string) (*cacheManifest, error) {
	path := manifestPath(cacheDir, source)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &cacheManifest{Source: source, Entries: map[string]cacheEntry{}}, nil
		}
		return nil, err
	}
	var m cacheManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return &cacheManifest{Source: source, Entries: map[string]cacheEntry{}}, nil
	}
	if m.Source == "" {
		m.Source = source
	}
	if m.Entries == nil {
		m.Entries = map[string]cacheEntry{}
	}
	return &m, nil
}

func saveCacheManifest(cacheDir string, m *cacheManifest) error {
	path := manifestPath(cacheDir, m.Source)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	payload, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
