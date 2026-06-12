package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/depx/internal/inventory"
	"github.com/projectdiscovery/depx/internal/malindex"
)

// progressReportEvery bounds how often record-build progress is reported so a
// 200k+ record stream does not spam the spinner.
const progressReportEvery = 2000

type inventorySyncer struct {
	cfg Config
}

func (s *inventorySyncer) compiledPath() string {
	return malindex.CompiledCachePath(s.cfg.CacheDir, "compiled")
}

func (s *inventorySyncer) sourceURL() string {
	if s.cfg.SourceURL != "" {
		return s.cfg.SourceURL
	}
	return inventory.SourceURL()
}

// loadIndex returns the malicious-package index, downloading the inventory when
// no local copy exists. With a usable local index it returns immediately and
// schedules a background refresh when the cache is older than MinInterval.
func (s *inventorySyncer) loadIndex(ctx context.Context, onProgress malindex.IndexLoadProgress, onStatus malindex.IndexLoadStatus) (*malindex.MaliciousIndex, error) {
	if idx, ok := s.loadCompiled(); ok && idx.PackageCount() > 0 {
		s.scheduleRefreshIfStale()
		return idx, nil
	}
	// No usable local index: fetch synchronously so the command has data.
	return s.sync(ctx, onProgress, onStatus)
}

func (s *inventorySyncer) loadCompiled() (*malindex.MaliciousIndex, bool) {
	if idx, ok := malindex.LoadCompiledIndexIfFresh(s.compiledPath()); ok {
		return idx, true
	}
	return malindex.LoadCompiledIndexStale(s.compiledPath())
}

func (s *inventorySyncer) needsRefresh(m *Manifest) bool {
	if m == nil || m.Sync.LastSuccess.IsZero() {
		return true
	}
	return time.Since(m.Sync.LastSuccess) >= s.cfg.MinInterval
}

func (s *inventorySyncer) scheduleRefreshIfStale() {
	m, _ := loadManifest(s.cfg.CacheDir, inventorySource)
	if !s.needsRefresh(m) {
		return
	}
	s.cfg.scheduleBackground(func(bg context.Context) {
		_, _ = s.sync(bg, nil, nil)
	})
}

// sync downloads the inventory export, builds the compiled index, and persists
// it. On any failure it leaves the existing on-disk index untouched and returns
// it (when present) so commands keep working on the last good data — there is
// no secondary source to fall back to.
func (s *inventorySyncer) sync(ctx context.Context, onProgress malindex.IndexLoadProgress, onStatus malindex.IndexLoadStatus) (*malindex.MaliciousIndex, error) {
	m, _ := loadManifest(s.cfg.CacheDir, inventorySource)
	if m == nil {
		m = newManifest(inventorySource)
	}
	m.Sync.State = "syncing"
	m.Sync.LastAttempt = time.Now().UTC()
	_ = saveManifest(s.cfg.CacheDir, m)

	if onStatus != nil {
		onStatus(malindex.WithFirstRunCacheNote("Downloading malicious package inventory…"))
	}

	idx := malindex.NewEmptyMaliciousIndex()
	loaded := 0
	snap, err := inventory.Fetch(ctx, s.sourceURL(), s.cfg.UserAgent, m.ETag, func(rec inventory.Record) error {
		idx.AddRecord(rec)
		loaded++
		if onProgress != nil && (loaded == 1 || loaded%progressReportEvery == 0) {
			onProgress(loaded, 0)
		}
		return nil
	})
	if err != nil {
		return s.failSync(m, err)
	}

	if snap.NotModified {
		if existing, ok := s.loadCompiled(); ok {
			m.Sync.State = "idle"
			m.Sync.LastSuccess = time.Now().UTC()
			m.Sync.LastError = ""
			_ = saveManifest(s.cfg.CacheDir, m)
			s.finish(onStatus, existing.PackageCount())
			return existing, nil
		}
		// Server reported not-modified but we have no local index: re-fetch
		// unconditionally by dropping the ETag.
		m.ETag = ""
		return s.failSync(m, fmt.Errorf("inventory not-modified but no local index"))
	}

	if err := malindex.SaveCompiledIndex(s.compiledPath(), loaded, idx); err != nil {
		return s.failSync(m, err)
	}

	m.ETag = snap.ETag
	m.GeneratedAt = snap.GeneratedAt
	m.Compiled = CompiledState{
		Path:         "mal/compiled.json",
		EntryCount:   loaded,
		PackageCount: idx.PackageCount(),
		BuiltAt:      time.Now().UTC(),
	}
	m.Sync.State = "idle"
	m.Sync.LastSuccess = time.Now().UTC()
	m.Sync.LastError = ""
	_ = saveManifest(s.cfg.CacheDir, m)

	if onProgress != nil {
		onProgress(loaded, loaded)
	}
	s.finish(onStatus, idx.PackageCount())
	return idx, nil
}

func (s *inventorySyncer) failSync(m *Manifest, cause error) (*malindex.MaliciousIndex, error) {
	m.Sync.State = "failed"
	m.Sync.LastError = cause.Error()
	_ = saveManifest(s.cfg.CacheDir, m)
	// Keep running on the last good index when one exists.
	if existing, ok := s.loadCompiled(); ok && existing.PackageCount() > 0 {
		return existing, nil
	}
	return nil, cause
}

func (s *inventorySyncer) finish(onStatus malindex.IndexLoadStatus, packages int) {
	if onStatus != nil {
		onStatus(fmt.Sprintf("Malicious package index ready (%d packages)", packages))
	}
}
