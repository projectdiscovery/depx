package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/depx/internal/osv"
)

const (
	osvDownloadWorkers = 20
	osvBlobRel         = "vulns"

	// vulnFetchRetries bounds how many times the OSV API fallback is retried
	// for a single record before it is marked failed.
	vulnFetchRetries      = 3
	vulnFetchRetryBackoff = 150 * time.Millisecond
)

type osvSyncer struct {
	cfg Config
}

func (s *osvSyncer) compiledPath() string {
	return osv.CompiledCachePath(s.cfg.CacheDir, "compiled")
}

func (s *osvSyncer) blobPath(id string) string {
	return filepath.Join(s.cfg.CacheDir, osvBlobRel, id+".json")
}

func (s *osvSyncer) loadIndex(ctx context.Context, foreground bool, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	manifest, err := loadManifest(s.cfg.CacheDir, "osv")
	if err != nil {
		return nil, err
	}

	blocking := foreground || onProgress != nil || onStatus != nil
	synced := manifestFullySynced(manifest)

	if !blocking || synced {
		if idx, ok := s.loadCompiled(manifest); ok && idx != nil && idx.PackageCount() > 0 {
			s.scheduleBackgroundSyncIfNeeded(manifest, foreground && idx.PackageCount() == 0)
			return idx, nil
		}

		if idx, ok := osv.LoadCompiledIndexStale(s.compiledPath()); ok && idx.PackageCount() > 0 {
			s.scheduleBackgroundSyncIfNeeded(manifest, false)
			return idx, nil
		}
	}

	_, compiledStatErr := os.Stat(s.compiledPath())
	compiledMissing := os.IsNotExist(compiledStatErr)
	needsCatalogRefresh := compiledMissing && (manifest.Compiled.PackageCount > 0 || !manifest.Compiled.BuiltAt.IsZero())

	if !needsCatalogRefresh && (!blocking || synced) {
		if idx, err := s.rebuildCompiledFromLocalBlobs(manifest, onProgress); err == nil && idx != nil && idx.PackageCount() > 0 {
			_ = saveManifest(s.cfg.CacheDir, manifest)
			s.scheduleBackgroundSyncIfNeeded(manifest, false)
			return idx, nil
		}
	}

	if !blocking && s.hasLocalVulnBlobs() && !needsCatalogRefresh {
		s.scheduleBackgroundSyncIfNeeded(manifest, false)
		return osv.NewEmptyMaliciousIndex(), nil
	}

	return s.runSync(ctx, manifest, onProgress, onStatus)
}

func manifestFullySynced(m *Manifest) bool {
	return m != nil && !m.Sync.LastSuccess.IsZero()
}

func (s *osvSyncer) fallbackCompiledAfterSyncError(manifest *Manifest, blocking bool) (*osv.MaliciousIndex, bool) {
	if blocking && !manifestFullySynced(manifest) {
		return nil, false
	}
	idx, ok := s.loadCompiled(manifest)
	return idx, ok
}

func (s *osvSyncer) scheduleBackgroundSyncIfNeeded(manifest *Manifest, forceEmpty bool) {
	if manifest == nil {
		return
	}
	if !forceEmpty && manifest.countPending() == 0 && !s.shouldSync(manifest) {
		return
	}
	s.cfg.scheduleBackground(func(bg context.Context) {
		_, _ = s.runSync(bg, manifest, nil, nil)
	})
}

func (s *osvSyncer) hasLocalVulnBlobs() bool {
	entries, err := os.ReadDir(filepath.Join(s.cfg.CacheDir, osvBlobRel))
	if err != nil {
		return false
	}
	for _, ent := range entries {
		if !ent.IsDir() && strings.HasSuffix(ent.Name(), ".json") {
			return true
		}
	}
	return false
}

func (s *osvSyncer) rebuildCompiledFromLocalBlobs(m *Manifest, onProgress osv.IndexLoadProgress) (*osv.MaliciousIndex, error) {
	vulnDir := filepath.Join(s.cfg.CacheDir, osvBlobRel)
	files, err := os.ReadDir(vulnDir)
	if err != nil {
		return nil, err
	}

	idx := osv.NewEmptyMaliciousIndex()
	loaded := 0
	total := len(files)
	for i, ent := range files {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(ent.Name(), ".json")
		vuln, ok := readVulnBlob(s.cfg.CacheDir, id)
		if !ok || vuln == nil || vuln.Withdrawn != "" {
			continue
		}
		idx.AddVuln(vuln)
		loaded++
		if onProgress != nil && (loaded == 1 || loaded%500 == 0 || i == total-1) {
			onProgress(loaded, total)
		}
	}
	if loaded == 0 {
		return nil, fmt.Errorf("no local vuln blobs")
	}

	path := s.compiledPath()
	if err := osv.SaveCompiledIndex(path, loaded, idx); err != nil {
		return nil, err
	}
	m.Compiled = CompiledState{
		Path:         filepath.Join("mal", "compiled.json"),
		EntryCount:   loaded,
		PackageCount: idx.PackageCount(),
		BuiltAt:      time.Now().UTC(),
	}
	return idx, nil
}

func (s *osvSyncer) runSync(ctx context.Context, manifest *Manifest, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	manifest.Sync.State = "syncing"
	manifest.Sync.LastAttempt = time.Now().UTC()
	_ = saveManifest(s.cfg.CacheDir, manifest)

	blocking := onProgress != nil || onStatus != nil

	entries, fingerprint, err := s.fetchCatalog(ctx)
	if err != nil {
		manifest.Sync.State = "failed"
		manifest.Sync.LastError = err.Error()
		_ = saveManifest(s.cfg.CacheDir, manifest)
		if idx, ok := s.fallbackCompiledAfterSyncError(manifest, blocking); ok {
			return idx, nil
		}
		return nil, err
	}

	pending := s.diffCatalog(manifest, entries, fingerprint)
	malEntries := osv.FilterMALEntries(entries)
	manifest.Catalog.MaliciousCount = len(malEntries)
	_ = saveManifest(s.cfg.CacheDir, manifest)

	if s.shouldBulkSeed(manifest, pending, len(malEntries)) {
		if onStatus != nil {
			onStatus(osv.WithFirstRunCacheNote("Downloading malicious package corpus from OSV…"))
		}
		idx, err := s.bulkSeedFromGCS(ctx, malEntries, manifest, onProgress, onStatus)
		if err != nil {
			manifest.Sync.State = "failed"
			manifest.Sync.LastError = err.Error()
			_ = saveManifest(s.cfg.CacheDir, manifest)
			if idx, ok := s.fallbackCompiledAfterSyncError(manifest, blocking); ok {
				return idx, nil
			}
			return nil, err
		}
		pending = s.pendingEntries(manifest)
		if len(pending) == 0 {
			manifest.Sync.State = "idle"
			manifest.Sync.LastSuccess = time.Now().UTC()
			manifest.Sync.LastError = ""
			manifest.Sync.Pending = 0
			_ = saveManifest(s.cfg.CacheDir, manifest)
			_ = writeFeedIndexCache(s.cfg.CacheDir, entries)
			if onStatus != nil {
				onStatus(fmt.Sprintf("Malicious package index ready (%d packages)", idx.PackageCount()))
			}
			return idx, nil
		}
	}

	if onStatus != nil && len(pending) > 0 {
		onStatus(fmt.Sprintf("Downloading %d updated malicious package records…", len(pending)))
	}

	if err := s.downloadPending(ctx, manifest, pending, onProgress); err != nil {
		manifest.Sync.State = "failed"
		manifest.Sync.LastError = err.Error()
		_ = saveManifest(s.cfg.CacheDir, manifest)
		if idx, ok := s.fallbackCompiledAfterSyncError(manifest, blocking); ok {
			return idx, nil
		}
		return nil, err
	}

	idx, err := s.rebuildCompiled(manifest, onProgress)
	if err != nil {
		manifest.Sync.State = "failed"
		manifest.Sync.LastError = err.Error()
		_ = saveManifest(s.cfg.CacheDir, manifest)
		return nil, err
	}

	manifest.Sync.State = "idle"
	manifest.Sync.LastSuccess = time.Now().UTC()
	manifest.Sync.LastError = ""
	manifest.Sync.Pending = manifest.countPending()
	_ = saveManifest(s.cfg.CacheDir, manifest)
	_ = writeFeedIndexCache(s.cfg.CacheDir, entries)

	if onStatus != nil {
		onStatus(fmt.Sprintf("Malicious package index ready (%d packages)", idx.PackageCount()))
	}
	return idx, nil
}

func (s *osvSyncer) shouldSync(m *Manifest) bool {
	if m.Catalog.Fingerprint == "" {
		return true
	}
	if m.Sync.LastSuccess.IsZero() {
		return true
	}
	return time.Since(m.Sync.LastSuccess) >= s.cfg.MinInterval
}

func (s *osvSyncer) fetchCatalog(ctx context.Context) ([]osv.IndexEntry, string, error) {
	url := osv.ModifiedIndexURLFromEnv()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)

	client := &http.Client{Timeout: s.cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("modified index: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(body)
	fingerprint := hex.EncodeToString(sum[:])

	entries, err := osv.ParseModifiedIndexBytes(body)
	if err != nil {
		return nil, "", err
	}
	return entries, fingerprint, nil
}

func (s *osvSyncer) diffCatalog(m *Manifest, remote []osv.IndexEntry, fingerprint string) []osv.IndexEntry {
	var latest time.Time
	for _, e := range remote {
		if e.Modified.After(latest) {
			latest = e.Modified
		}
	}
	m.Catalog.Fingerprint = fingerprint
	m.Catalog.EntryCount = len(remote)
	m.Catalog.LatestModified = latest
	m.Catalog.FetchedAt = time.Now().UTC()

	seen := make(map[string]struct{}, len(remote))
	var pending []osv.IndexEntry
	for _, e := range remote {
		seen[e.ID] = struct{}{}
		cur, ok := m.Entries[e.ID]
		// Skip entries already resolved at this revision: ready (fetched) or
		// withdrawn-at-source. Re-fetching withdrawn entries every sync only
		// re-discovers the same withdrawal and wastes requests.
		if ok && cur.Modified.Equal(e.Modified) &&
			(cur.Status == EntryReady || cur.Status == EntryWithdrawn) {
			continue
		}
		m.Entries[e.ID] = EntryRecord{
			Ecosystem: e.Ecosystem,
			Modified:  e.Modified,
			Blob:      filepath.Join(osvBlobRel, e.ID+".json"),
			Status:    EntryPending,
		}
		pending = append(pending, e)
	}

	for id, rec := range m.Entries {
		if _, ok := seen[id]; ok {
			continue
		}
		if rec.Status == EntryWithdrawn {
			continue
		}
		rec.Status = EntryWithdrawn
		m.Entries[id] = rec
	}
	m.Sync.Pending = len(pending)
	return pending
}

func blobExists(cacheDir, id string) bool {
	_, err := os.Stat(filepath.Join(cacheDir, osvBlobRel, id+".json"))
	return err == nil
}

func (s *osvSyncer) downloadPending(ctx context.Context, m *Manifest, pending []osv.IndexEntry, onProgress osv.IndexLoadProgress) error {
	if len(pending) == 0 {
		return nil
	}
	var loaded atomic.Int32
	total := len(pending)
	report := func() {
		if onProgress != nil {
			onProgress(int(loaded.Load()), total)
		}
	}

	jobs := make(chan osv.IndexEntry)
	var wg sync.WaitGroup
	var mu sync.Mutex

	workerCount := osvDownloadWorkers
	if workerCount > len(pending) {
		workerCount = len(pending)
	}

	process := func(e osv.IndexEntry) {
		vuln, err := s.fetchVulnBlob(ctx, e)

		status := EntryReady
		var fetchedAt time.Time
		counted := false
		switch {
		case err != nil || vuln == nil:
			status = EntryFailed
		case vuln.Withdrawn != "":
			status = EntryWithdrawn
		default:
			if werr := writeVulnBlob(s.cfg.CacheDir, e.ID, vuln); werr != nil {
				status = EntryFailed
			} else {
				fetchedAt = time.Now().UTC()
				counted = true
			}
		}

		mu.Lock()
		rec := m.Entries[e.ID]
		rec.Status = status
		if !fetchedAt.IsZero() {
			rec.FetchedAt = fetchedAt
		}
		m.Entries[e.ID] = rec
		mu.Unlock()

		if counted {
			loaded.Add(1)
			report()
		}
	}

	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for e := range jobs {
				if ctx.Err() != nil {
					return
				}
				process(e)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, entry := range pending {
			select {
			case <-ctx.Done():
				return
			case jobs <- entry:
			}
		}
	}()

	wg.Wait()
	if onProgress != nil {
		onProgress(total, total)
	}
	return ctx.Err()
}

func (s *osvSyncer) fetchVulnBlob(ctx context.Context, e osv.IndexEntry) (*osv.Vulnerability, error) {
	if vuln, ok := readVulnBlob(s.cfg.CacheDir, e.ID); ok {
		if !vuln.ModifiedTime().Before(e.Modified) {
			return vuln, nil
		}
	}

	if vuln, err := s.fetchVulnHTTP(ctx, osv.GCSVulnJSONURL(e.Ecosystem, e.ID)); err == nil {
		return vuln, nil
	}

	// Fall back to the OSV API. Retry transient failures with a short backoff so
	// a single network blip doesn't permanently mark the record as failed until
	// the next index change.
	fallbackURL := osv.BaseURLFromEnv() + "/vulns/" + e.ID
	var lastErr error
	for attempt := 0; attempt < vulnFetchRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * vulnFetchRetryBackoff):
			}
		}
		vuln, err := s.fetchVulnHTTP(ctx, fallbackURL)
		if err == nil {
			return vuln, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (s *osvSyncer) fetchVulnHTTP(ctx context.Context, url string) (*osv.Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	client := &http.Client{Timeout: s.cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vuln fetch %s: status %d", url, resp.StatusCode)
	}
	var vuln osv.Vulnerability
	if err := json.NewDecoder(io.LimitReader(resp.Body, osv.MaxVulnResponseBytes)).Decode(&vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

func writeVulnBlob(cacheDir, id string, vuln *osv.Vulnerability) error {
	path := filepath.Join(cacheDir, osvBlobRel, id+".json")
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readVulnBlob(cacheDir, id string) (*osv.Vulnerability, bool) {
	path := filepath.Join(cacheDir, osvBlobRel, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var wrap struct {
		Record osv.Vulnerability `json:"record"`
	}
	if err := json.Unmarshal(data, &wrap); err != nil {
		return nil, false
	}
	return &wrap.Record, true
}

func (s *osvSyncer) rebuildCompiled(m *Manifest, onProgress osv.IndexLoadProgress) (*osv.MaliciousIndex, error) {
	idx := osv.NewEmptyMaliciousIndex()
	ready := 0
	total := m.countReady()
	for id, rec := range m.Entries {
		if rec.Status != EntryReady {
			continue
		}
		vuln, ok := readVulnBlob(s.cfg.CacheDir, id)
		if !ok || vuln == nil {
			rec.Status = EntryPending
			m.Entries[id] = rec
			continue
		}
		if vuln.Withdrawn != "" {
			rec.Status = EntryWithdrawn
			m.Entries[id] = rec
			continue
		}
		idx.AddVuln(vuln)
		ready++
		if onProgress != nil && (ready == 1 || ready%250 == 0 || ready == total) {
			onProgress(ready, total)
		}
	}

	path := s.compiledPath()
	if err := osv.SaveCompiledIndex(path, m.Catalog.EntryCount, idx); err != nil {
		return nil, err
	}
	m.Compiled = CompiledState{
		Path:         filepath.Join("mal", "compiled.json"),
		EntryCount:   m.Catalog.EntryCount,
		PackageCount: idx.PackageCount(),
		BuiltAt:      time.Now().UTC(),
	}
	return idx, nil
}

func (s *osvSyncer) shouldBulkSeed(m *Manifest, pending []osv.IndexEntry, malCatalogSize int) bool {
	if m == nil || !m.Sync.LastSuccess.IsZero() {
		return false
	}
	if malCatalogSize < osv.ZipMALThreshold {
		return false
	}
	// Initial corpus: pending is essentially the full malicious catalog.
	return len(pending) >= malCatalogSize/2
}

func (s *osvSyncer) bulkSeedFromGCS(ctx context.Context, malEntries []osv.IndexEntry, m *Manifest, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	idx, err := osv.BuildMaliciousIndexFromGCS(ctx, s.cfg.CacheDir, s.cfg.UserAgent, s.cfg.Timeout, malEntries, onProgress, onStatus)
	if err != nil {
		return nil, err
	}
	s.markManifestReadyFromBlobs(m, malEntries)
	path := s.compiledPath()
	if err := osv.SaveCompiledIndex(path, len(malEntries), idx); err != nil {
		return nil, err
	}
	m.Compiled = CompiledState{
		Path:         filepath.Join("mal", "compiled.json"),
		EntryCount:   len(malEntries),
		PackageCount: idx.PackageCount(),
		BuiltAt:      time.Now().UTC(),
	}
	m.Sync.Pending = m.countPending()
	return idx, nil
}

func (s *osvSyncer) markManifestReadyFromBlobs(m *Manifest, entries []osv.IndexEntry) {
	now := time.Now().UTC()
	for _, e := range entries {
		if !blobExists(s.cfg.CacheDir, e.ID) {
			continue
		}
		rec := m.Entries[e.ID]
		rec.Ecosystem = e.Ecosystem
		rec.Modified = e.Modified
		rec.Blob = filepath.Join(osvBlobRel, e.ID+".json")
		rec.Status = EntryReady
		rec.FetchedAt = now
		m.Entries[e.ID] = rec
	}
}

func (s *osvSyncer) pendingEntries(m *Manifest) []osv.IndexEntry {
	if m == nil {
		return nil
	}
	out := make([]osv.IndexEntry, 0, m.countPending())
	for id, rec := range m.Entries {
		if rec.Status != EntryPending {
			continue
		}
		out = append(out, osv.IndexEntry{
			ID:        id,
			Ecosystem: rec.Ecosystem,
			Modified:  rec.Modified,
		})
	}
	return out
}

func (s *osvSyncer) loadCompiled(m *Manifest) (*osv.MaliciousIndex, bool) {
	path := s.compiledPath()
	if idx, ok := osv.LoadCompiledIndexIfFresh(path); ok {
		return idx, true
	}
	if idx, ok := osv.LoadCompiledIndexStale(path); ok {
		return idx, true
	}
	if m.Compiled.BuiltAt.IsZero() {
		return osv.LoadCompiledIndex(path, m.Catalog.EntryCount)
	}
	if time.Since(m.Compiled.BuiltAt) > 30*24*time.Hour {
		return nil, false
	}
	return osv.LoadCompiledIndex(path, m.Catalog.EntryCount)
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
