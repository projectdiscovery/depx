package sync

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const (
	manifestSchemaVersion = 2
	// inventorySource is the single intel source identifier used for the
	// manifest directory and status reporting.
	inventorySource = "inventory"
)

// Manifest tracks the state of the local malicious-package inventory: the
// upstream revision (ETag + generated_at) last ingested and the compiled
// index built from it.
type Manifest struct {
	SchemaVersion int           `json:"schema_version"`
	Source        string        `json:"source"`
	ETag          string        `json:"etag,omitempty"`
	GeneratedAt   time.Time     `json:"generated_at,omitempty"`
	Compiled      CompiledState `json:"compiled"`
	Sync          SyncState     `json:"sync"`
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
	LastError   string    `json:"last_error,omitempty"`
}

func manifestPath(cacheDir, source string) string {
	return filepath.Join(cacheDir, "sync", source, "manifest.json")
}

func loadManifest(cacheDir, source string) (*Manifest, error) {
	return LoadManifest(cacheDir, source)
}

// LoadManifest reads the inventory sync manifest, returning a fresh one when
// absent or unparsable.
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
	return &m, nil
}

func newManifest(source string) *Manifest {
	return &Manifest{
		SchemaVersion: manifestSchemaVersion,
		Source:        source,
		Sync:          SyncState{State: "idle"},
	}
}

func saveManifest(cacheDir string, m *Manifest) error {
	return SaveManifest(cacheDir, m)
}

// SaveManifest persists the inventory sync manifest atomically.
func SaveManifest(cacheDir string, m *Manifest) error {
	path := manifestPath(cacheDir, m.Source)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
