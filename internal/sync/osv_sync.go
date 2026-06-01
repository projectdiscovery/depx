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
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/depx/internal/osv"
)

const (
	osvDownloadWorkers = 20
	osvBlobRel         = "vulns"
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

	idx, ok := s.loadCompiled(manifest)
	if ok && idx != nil {
		if onProgress != nil {
			onProgress(manifest.Compiled.PackageCount, manifest.Compiled.PackageCount)
		}
		if manifest.countPending() > 0 || s.shouldSync(manifest) {
			if foreground && idx.PackageCount() == 0 {
				return s.runSync(ctx, manifest, onProgress, onStatus)
			}
			s.cfg.scheduleBackground(func(bg context.Context) {
				_, _ = s.runSync(bg, manifest, nil, nil)
			})
		}
		return idx, nil
	}

	return s.runSync(ctx, manifest, onProgress, onStatus)
}

func (s *osvSyncer) runSync(ctx context.Context, manifest *Manifest, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	manifest.Sync.State = "syncing"
	manifest.Sync.LastAttempt = time.Now().UTC()
	_ = saveManifest(s.cfg.CacheDir, manifest)

	entries, fingerprint, err := s.fetchCatalog(ctx)
	if err != nil {
		manifest.Sync.State = "failed"
		manifest.Sync.LastError = err.Error()
		_ = saveManifest(s.cfg.CacheDir, manifest)
		if idx, ok := s.loadCompiled(manifest); ok {
			return idx, nil
		}
		return nil, err
	}

	pending := s.diffCatalog(manifest, entries, fingerprint)
	if onStatus != nil && len(pending) > 0 {
		onStatus(fmt.Sprintf("Downloading %d updated malicious package records…", len(pending)))
	}

	if err := s.downloadPending(ctx, manifest, pending, onProgress); err != nil {
		manifest.Sync.State = "failed"
		manifest.Sync.LastError = err.Error()
		_ = saveManifest(s.cfg.CacheDir, manifest)
		if idx, ok := s.loadCompiled(manifest); ok {
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
		if ok && cur.Status == EntryReady && cur.Modified.Equal(e.Modified) {
			continue
		}
		if ok && cur.Status == EntryReady && blobExists(s.cfg.CacheDir, e.ID) {
			// modified timestamp changed but blob may still be valid — re-fetch
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

	sem := make(chan struct{}, osvDownloadWorkers)
	var wg sync.WaitGroup
	for _, entry := range pending {
		wg.Add(1)
		go func(e osv.IndexEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			vuln, err := s.fetchVulnBlob(ctx, e)
			rec := m.Entries[e.ID]
			if err != nil || vuln == nil || vuln.Withdrawn != "" {
				rec.Status = EntryFailed
				m.Entries[e.ID] = rec
				return
			}
			if err := writeVulnBlob(s.cfg.CacheDir, e.ID, vuln); err != nil {
				rec.Status = EntryFailed
				m.Entries[e.ID] = rec
				return
			}
			rec.Status = EntryReady
			rec.FetchedAt = time.Now().UTC()
			m.Entries[e.ID] = rec
			loaded.Add(1)
			report()
		}(entry)
	}
	wg.Wait()
	if onProgress != nil {
		onProgress(total, total)
	}
	return nil
}

func (s *osvSyncer) fetchVulnBlob(ctx context.Context, e osv.IndexEntry) (*osv.Vulnerability, error) {
	if vuln, ok := readVulnBlob(s.cfg.CacheDir, e.ID); ok {
		if !vuln.ModifiedTime().Before(e.Modified) {
			return vuln, nil
		}
	}

	vuln, err := s.fetchVulnHTTP(ctx, osv.GCSVulnJSONURL(e.Ecosystem, e.ID))
	if err == nil {
		return vuln, nil
	}
	return s.fetchVulnHTTP(ctx, osv.BaseURLFromEnv()+"/vulns/"+e.ID)
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
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
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

func (s *osvSyncer) loadCompiled(m *Manifest) (*osv.MaliciousIndex, bool) {
	path := s.compiledPath()
	if m.Compiled.BuiltAt.IsZero() {
		idx, ok := osv.LoadCompiledIndexIfFresh(path)
		if ok {
			return idx, true
		}
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
		FetchedAt time.Time         `json:"fetched_at"`
		Entries   []osv.IndexEntry  `json:"entries"`
	}{
		FetchedAt: time.Now().UTC(),
		Entries:   entries,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}
