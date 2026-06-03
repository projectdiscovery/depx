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
	EntryPending   EntryStatus = "pending"
	EntryReady     EntryStatus = "ready"
	EntryFailed    EntryStatus = "failed"
	EntryWithdrawn EntryStatus = "withdrawn"
)

type Manifest struct {
	SchemaVersion int                    `json:"schema_version"`
	Source        string                 `json:"source"`
	Catalog       CatalogState           `json:"catalog"`
	Entries       map[string]EntryRecord `json:"entries"`
	Compiled      CompiledState          `json:"compiled"`
	Sync          SyncState              `json:"sync"`
}

type CatalogState struct {
	Fingerprint    string    `json:"fingerprint"`
	EntryCount     int       `json:"entry_count"`
	MaliciousCount int       `json:"malicious_count,omitempty"`
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
	payload, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// Write to a uniquely-named temp file in the same dir, then rename. A shared
	// ".tmp" name would let overlapping writers clobber each other and rename a
	// torn payload, surfacing as "unexpected end of JSON input" on read.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// countPending reports entries still awaiting a first successful fetch. Failed
// (per-entry EntryFailed) and withdrawn entries are excluded: failures retain
// their own status and withdrawn advisories are intentionally outside the
// corpus, so neither should surface as outstanding sync work.
func (m *Manifest) countPending() int {
	n := 0
	for _, e := range m.Entries {
		if e.Status == EntryPending {
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
