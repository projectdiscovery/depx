package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/source"
	syncengine "github.com/projectdiscovery/depx/internal/sync"
)

type osvProvider struct {
	client  *osv.Client
	cfg     *config.Config
	engine  *syncengine.Engine
	version string

	feedRefreshMu  sync.Mutex
	feedRefreshing bool
}

func NewOSV(version string, cfg *config.Config) Provider {
	client := osv.NewClient(version, cfg.Timeout, osv.WithCache(cfg.CacheDir, cfg.Feed.CacheTTL))
	return &osvProvider{
		client:  client,
		cfg:     cfg,
		engine:  newSyncEngine(version, cfg),
		version: version,
	}
}

func (p *osvProvider) Name() string { return "osv" }

func (p *osvProvider) StartBackgroundSync(ctx context.Context) {
	p.engine.StartBackground(ctx)
}

func (p *osvProvider) SyncStatus() syncengine.Status {
	return p.engine.StatusSnapshot()
}

func (p *osvProvider) GetVuln(ctx context.Context, id string) (*osv.Vulnerability, error) {
	return p.client.GetVuln(ctx, id)
}

func (p *osvProvider) Query(ctx context.Context, q osv.QueryRequest) (*osv.QueryResponse, error) {
	return p.client.Query(ctx, q)
}

func (p *osvProvider) QueryBatch(ctx context.Context, queries []osv.QueryRequest) (*osv.BatchQueryResponse, error) {
	return p.client.QueryBatch(ctx, queries)
}

func (p *osvProvider) LoadMaliciousIndex(ctx context.Context, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	return p.engine.LoadIndex(ctx, onProgress, onStatus)
}

func (p *osvProvider) VulnPageURL(id string) string { return osv.VulnPageURL(id) }

func (p *osvProvider) Feed(ctx context.Context, req FeedRequest) (*FeedResponse, error) {
	if req.Since == 0 {
		req.Since = p.cfg.Feed.Since
	}
	if req.Limit == 0 {
		req.Limit = p.cfg.Feed.Limit
	}

	sinceTime := time.Now().UTC().Add(-req.Since)

	var entries []source.PackageEntry
	fromCache := false
	total := 0

	compiledPath := osv.CompiledCachePath(p.cfg.CacheDir, "compiled")
	if hits, ok := osv.LoadPublishedFeedSnapshot(p.cfg.CacheDir, compiledPath); ok {
		filtered := osv.FilterFeedHits(hits, sinceTime, req.Ecosystem)
		entries = p.packageEntriesFromHits(filtered)
		total = len(entries)
		fromCache = true
	} else if idx, ok := p.loadFeedCompiledIndex(); ok {
		entries = p.packageEntriesFromHits(idx.ListSincePublished(sinceTime, req.Ecosystem))
		total = len(entries)
		_ = osv.WritePublishedFeedSnapshot(p.cfg.CacheDir, compiledPath, idx)
	} else {
		index, cached, err := p.loadFeedIndex(ctx)
		if err != nil {
			return nil, err
		}
		fromCache = cached
		filtered := filterOSVIndexByEcosystem(index, req.Ecosystem)
		entries = p.packageEntriesFromModifiedRows(filtered)
		entries = filterPackageEntriesByPublished(entries, sinceTime)
		total = len(entries)
	}

	source.SortPackageEntriesByPublished(entries)
	p.enrichFeedEntriesFromCache(entries)
	windowStats := source.ComputeWindowStats(entries)

	limit := req.Limit
	if limit <= 0 || limit > len(entries) {
		limit = len(entries)
	}
	entries = entries[:limit]

	return &FeedResponse{
		Entries:     entries,
		WindowStats: windowStats,
		Total:       total,
		FromCache:   fromCache,
	}, nil
}

func (p *osvProvider) loadFeedIndex(ctx context.Context) ([]osv.IndexEntry, bool, error) {
	cachePath := filepath.Join(p.cfg.CacheDir, "feed", "index.json")
	if cached, err := readOSVFeedIndexCache(cachePath, p.cfg.Feed.CacheTTL); err == nil {
		return cached, true, nil
	}

	// Stale cache: return immediately and refresh in the background.
	if cached, err := readOSVFeedIndexCacheStale(cachePath); err == nil {
		p.scheduleFeedIndexRefresh()
		return cached, true, nil
	}

	// No feed cache on disk yet: fetch synchronously.
	index, err := osv.StreamModifiedIndex(ctx, osv.ModifiedIndexURLFromEnv(), p.clientUserAgent(), p.cfg.Timeout)
	if err != nil {
		return nil, false, err
	}
	_ = writeOSVFeedIndexCache(cachePath, index)
	return index, false, nil
}

func (p *osvProvider) scheduleFeedIndexRefresh() {
	p.feedRefreshMu.Lock()
	if p.feedRefreshing {
		p.feedRefreshMu.Unlock()
		return
	}
	p.feedRefreshing = true
	p.feedRefreshMu.Unlock()

	go func() {
		defer func() {
			p.feedRefreshMu.Lock()
			p.feedRefreshing = false
			p.feedRefreshMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
		defer cancel()
		index, err := osv.StreamModifiedIndex(ctx, osv.ModifiedIndexURLFromEnv(), p.clientUserAgent(), p.cfg.Timeout)
		if err != nil {
			return
		}
		cachePath := filepath.Join(p.cfg.CacheDir, "feed", "index.json")
		_ = writeOSVFeedIndexCache(cachePath, index)
	}()
}

func (p *osvProvider) clientUserAgent() string {
	return "depx (+https://github.com/projectdiscovery/depx)"
}

func filterOSVIndexByEcosystem(index []osv.IndexEntry, ecosystem string) []osv.IndexEntry {
	if ecosystem == "" {
		return index
	}
	out := make([]osv.IndexEntry, 0)
	for _, row := range index {
		if matchFeedEco(row.Ecosystem, ecosystem) {
			out = append(out, row)
		}
	}
	return out
}

func filterPackageEntriesByPublished(entries []source.PackageEntry, since time.Time) []source.PackageEntry {
	out := make([]source.PackageEntry, 0, len(entries))
	for _, entry := range entries {
		at := entry.Published
		if at.IsZero() {
			at = entry.ModifiedAt
		}
		if at.IsZero() || at.Before(since) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func matchFeedEco(indexEco, filter string) bool {
	return osv.NormalizeEcosystem(indexEco) == osv.NormalizeEcosystem(filter)
}

func applyOSVVuln(entry *source.PackageEntry, vuln *osv.Vulnerability) {
	source.EnrichFromVuln(entry, vuln)
}

func (p *osvProvider) packageEntriesFromModifiedRows(rows []osv.IndexEntry) []source.PackageEntry {
	entries := make([]source.PackageEntry, 0, len(rows))
	for _, row := range rows {
		entry := source.PackageEntry{
			Ecosystem:  row.Ecosystem,
			IDs:        []string{row.ID},
			ModifiedAt: row.Modified,
		}
		if vuln, ok := p.client.GetVulnCachedOnly(row.ID); ok {
			applyOSVVuln(&entry, vuln)
		}
		entries = append(entries, entry)
	}
	return entries
}

func (p *osvProvider) loadFeedCompiledIndex() (*osv.MaliciousIndex, bool) {
	path := osv.CompiledCachePath(p.cfg.CacheDir, "compiled")
	if idx, ok := osv.LoadCompiledIndexIfFresh(path); ok {
		return idx, true
	}
	return osv.LoadCompiledIndexStale(path)
}

func (p *osvProvider) packageEntriesFromHits(hits []osv.SearchHit) []source.PackageEntry {
	entries := make([]source.PackageEntry, 0, len(hits))
	for _, hit := range hits {
		entry := source.PackageEntry{
			Ecosystem:  hit.Ecosystem,
			Name:       hit.Name,
			IDs:        append([]string(nil), hit.IDs...),
			Summary:    hit.Summary,
			Published:  hit.Published,
			ModifiedAt: hit.Modified,
		}
		if len(hit.IDs) > 0 {
			if vuln, ok := p.client.GetVulnCachedOnly(hit.IDs[0]); ok {
				applyOSVVuln(&entry, vuln)
			}
		}
		if entry.Name != "" && entry.Ecosystem != "" && entry.PackageURL == "" {
			entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
		}
		entries = append(entries, entry)
	}
	return entries
}

func applyListing(entry *source.PackageEntry, hit osv.SearchHit) {
	if hit.Summary != "" {
		entry.Summary = hit.Summary
	}
	if hit.Name != "" {
		entry.Name = hit.Name
	}
	if hit.Ecosystem != "" && entry.Ecosystem == "" {
		entry.Ecosystem = hit.Ecosystem
	}
	if !hit.Published.IsZero() && entry.Published.IsZero() {
		entry.Published = hit.Published
	}
	if !hit.Modified.IsZero() && entry.ModifiedAt.IsZero() {
		entry.ModifiedAt = hit.Modified
	}
	if entry.Name != "" && entry.Ecosystem != "" && entry.PackageURL == "" {
		entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
	}
}

// enrichFeedEntryFromCache fills missing display fields from local cache only.
// Feed rendering must never block on network fetches. Pass a shared compiled index
// when enriching many entries to avoid reloading compiled.json repeatedly.
func (p *osvProvider) enrichFeedEntryFromCache(entry *source.PackageEntry, compiled *osv.MaliciousIndex) {
	if entry == nil || len(entry.IDs) == 0 {
		return
	}
	id := entry.IDs[0]
	if entry.Name == "" || entry.Ecosystem == "" || entry.Summary == "" {
		idx := compiled
		if idx == nil {
			if loaded, ok := p.loadFeedCompiledIndex(); ok {
				idx = loaded
			}
		}
		if idx != nil {
			if hit, ok := idx.LookupByID(id); ok {
				applyListing(entry, hit)
			}
		}
	}
	if vuln, ok := p.client.GetVulnCachedOnly(id); ok {
		applyOSVVuln(entry, vuln)
	}
	if entry.Name != "" && entry.Ecosystem != "" && entry.PackageURL == "" {
		entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
	}
}

func (p *osvProvider) enrichFeedEntriesFromCache(entries []source.PackageEntry) {
	var compiled *osv.MaliciousIndex
	for i := range entries {
		if entries[i].Name != "" && entries[i].Ecosystem != "" && entries[i].Summary != "" {
			p.enrichFeedEntryFromCache(&entries[i], nil)
			continue
		}
		if compiled == nil {
			if idx, ok := p.loadFeedCompiledIndex(); ok {
				compiled = idx
			}
		}
		p.enrichFeedEntryFromCache(&entries[i], compiled)
	}
}

type cachedFeedIndex struct {
	FetchedAt time.Time        `json:"fetched_at"`
	Entries   []osv.IndexEntry `json:"entries"`
}

func readOSVFeedIndexCache(path string, ttl time.Duration) ([]osv.IndexEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cached cachedFeedIndex
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, err
	}
	if time.Since(cached.FetchedAt) > ttl {
		return nil, fmt.Errorf("cache expired")
	}
	return cached.Entries, nil
}

func readOSVFeedIndexCacheStale(path string) ([]osv.IndexEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cached cachedFeedIndex
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, err
	}
	return cached.Entries, nil
}

func writeOSVFeedIndexCache(path string, entries []osv.IndexEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.Marshal(cachedFeedIndex{
		FetchedAt: time.Now().UTC(),
		Entries:   entries,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}

func (p *osvProvider) Search(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	if req.Limit <= 0 {
		req.Limit = p.cfg.Feed.Limit
	}
	idx, err := p.LoadMaliciousIndex(ctx, req.OnProgress, req.OnStatus)
	if err != nil {
		return nil, err
	}
	match := idx.Search(req.Query, req.Ecosystem, req.Limit)
	entries := make([]source.PackageEntry, 0, len(match.Hits))
	for _, hit := range match.Hits {
		entry := source.PackageEntry{
			Ecosystem:  hit.Ecosystem,
			Name:       hit.Name,
			IDs:        append([]string(nil), hit.IDs...),
			Summary:    hit.Summary,
			Published:  hit.Published,
			ModifiedAt: hit.Modified,
		}
		p.enrichFeedEntryFromCache(&entry, nil)
		entries = append(entries, entry)
	}
	return &SearchResponse{
		Entries: entries,
		Total:   match.Total,
	}, nil
}
