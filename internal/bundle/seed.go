package bundle

import (
	"os"
	"path/filepath"
	"time"
)

func embeddedSeedDisabled() bool {
	switch os.Getenv("DEPX_DISABLE_EMBEDDED_SEED") {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// SeedIfNeeded extracts the embedded bundle when cache is missing or older than the embedded baseline.
func SeedIfNeeded(cacheDir, source string) (bool, error) {
	if embeddedSeedDisabled() {
		return false, nil
	}
	tarball, ok := bytesForSource(source)
	if !ok || len(tarball) == 0 {
		return false, nil
	}

	embedded, err := peekMeta(tarball)
	if err != nil {
		return false, err
	}
	if !needsSeed(cacheDir, source, embedded) {
		return false, nil
	}

	meta, err := Extract(cacheDir, tarball)
	if err != nil {
		return false, err
	}

	m, err := loadCacheManifest(cacheDir, source)
	if err != nil {
		return false, err
	}
	m.Seed = &cacheSeedState{
		Source:          "embedded",
		EmbeddedBuiltAt: meta.BuiltAt,
		EmbeddedVersion: meta.SchemaVersion,
		LastSeedAt:      time.Now().UTC(),
	}
	if m.Sync.State == "" {
		m.Sync.State = "idle"
	}
	if m.Sync.LastSuccess.IsZero() {
		m.Sync.LastSuccess = meta.BuiltAt
	}
	return true, saveCacheManifest(cacheDir, m)
}

func needsSeed(cacheDir, source string, embedded Meta) bool {
	if embedded.BuiltAt.IsZero() {
		return false
	}
	if !compiledExists(cacheDir, source) {
		return true
	}
	m, err := loadCacheManifest(cacheDir, source)
	if err != nil {
		return true
	}
	if m.Compiled.BuiltAt.IsZero() {
		return true
	}
	if m.Compiled.BuiltAt.Before(embedded.BuiltAt) {
		return true
	}
	if m.Seed != nil && !m.Seed.EmbeddedBuiltAt.IsZero() && m.Seed.EmbeddedBuiltAt.Before(embedded.BuiltAt) {
		return true
	}
	return false
}

func compiledExists(cacheDir, source string) bool {
	name := "compiled"
	if source == "pd" {
		name = "pd_compiled"
	}
	_, err := os.Stat(filepath.Join(cacheDir, "mal", name+".json"))
	return err == nil
}
