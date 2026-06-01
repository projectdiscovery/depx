package sync

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const manifestSchemaVersion = 1

type EntryStatus string

const (
	EntryPending    EntryStatus = "pending"
	EntryReady      EntryStatus = "ready"
	EntryFailed     EntryStatus = "failed"
	EntryWithdrawn  EntryStatus = "withdrawn"
)

type Manifest struct {
	SchemaVersion int                    `json:"schema_version"`
	Source        string                 `json:"source"`
	Catalog       CatalogState           `json:"catalog"`
	Entries       map[string]EntryRecord `json:"entries"`
	Compiled      CompiledState          `json:"compiled"`
	Sync          SyncState              `json:"sync"`
	Seed          *SeedState             `json:"seed,omitempty"`
}

type CatalogState struct {
	Fingerprint    string    `json:"fingerprint"`
	EntryCount     int       `json:"entry_count"`
	LatestModified time.Time `json:"latest_modified,omitempty"`
	FetchedAt      time.Time `json:"fetched_at,omitempty"`
}

type EntryRecord struct {
	Ecosystem string      `json:"ecosystem"`
	Modified  time.Time   `json:"modified"`
	Blob      string      `json:"blob"`
	Status    EntryStatus `json:"status"`
	FetchedAt time.Time   `json:"fetched_at,omitempty"`
}

type CompiledState struct {
	Path         string    `json:"path"`
	EntryCount   int       `json:"entry_count"`
	PackageCount int       `json:"package_count"`
	BuiltAt      time.Time `json:"built_at,omitempty"`
}

type SyncState struct {
	State       string    `json:"state"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	Pending     int       `json:"pending"`
	LastError   string    `json:"last_error,omitempty"`
}

type SeedState struct {
	Source          string    `json:"source"`
	EmbeddedBuiltAt time.Time `json:"embedded_built_at,omitempty"`
	EmbeddedVersion int       `json:"embedded_version,omitempty"`
	LastSeedAt      time.Time `json:"last_seed_at,omitempty"`
}

func manifestPath(cacheDir, source string) string {
	return filepath.Join(cacheDir, "sync", source, "manifest.json")
}

func loadManifest(cacheDir, source string) (*Manifest, error) {
	return LoadManifest(cacheDir, source)
}

// LoadManifest reads the sync manifest for a source.
func LoadManifest(cacheDir, source string) (*Manifest, error) {
	path := manifestPath(cacheDir, source)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return newManifest(source), nil
		}
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return newManifest(source), nil
	}
	if m.SchemaVersion == 0 {
		m.SchemaVersion = manifestSchemaVersion
	}
	if m.Source == "" {
		m.Source = source
	}
	if m.Entries == nil {
		m.Entries = map[string]EntryRecord{}
	}
	return &m, nil
}

func newManifest(source string) *Manifest {
	return &Manifest{
		SchemaVersion: manifestSchemaVersion,
		Source:        source,
		Entries:       map[string]EntryRecord{},
		Sync:          SyncState{State: "idle"},
	}
}

func saveManifest(cacheDir string, m *Manifest) error {
	return SaveManifest(cacheDir, m)
}

// SaveManifest persists the sync manifest for a source.
func SaveManifest(cacheDir string, m *Manifest) error {
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

func (m *Manifest) countPending() int {
	n := 0
	for _, e := range m.Entries {
		if e.Status == EntryPending || e.Status == EntryFailed {
			n++
		}
	}
	return n
}

func (m *Manifest) countReady() int {
	n := 0
	for _, e := range m.Entries {
		if e.Status == EntryReady {
			n++
		}
	}
	return n
}
