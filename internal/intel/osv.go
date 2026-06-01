package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/source"
	"github.com/projectdiscovery/depx/internal/sync"
)

type osvProvider struct {
	client *osv.Client
	cfg    *config.Config
	engine *sync.Engine
}

func NewOSV(version string, cfg *config.Config) Provider {
	client := osv.NewClient(version, cfg.Timeout, osv.WithCache(cfg.CacheDir, cfg.Feed.CacheTTL))
	return &osvProvider{
		client: client,
		cfg:    cfg,
		engine:   newSyncEngine(version, cfg),
	}
}

func (p *osvProvider) Name() string { return "osv" }

func (p *osvProvider) StartBackgroundSync(ctx context.Context) {
	p.engine.StartBackground(ctx)
}

func (p *osvProvider) SyncStatus() sync.Status {
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
	if err := seedIntelCache(p.cfg.CacheDir, "osv"); err != nil {
		return nil, err
	}
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

	index, fromCache, err := p.loadFeedIndex(ctx)
	if err != nil {
		return nil, err
	}

	filtered := filterOSVIndex(index, sinceTime, req.Ecosystem)
	total := len(filtered)

	limit := req.Limit
	if limit <= 0 || limit > len(filtered) {
		limit = len(filtered)
	}
	page := filtered[:limit]

	entries := make([]source.PackageEntry, 0, len(page))
	for _, row := range page {
		entry := source.PackageEntry{
			Ecosystem:  row.Ecosystem,
			IDs:        []string{row.ID},
			ModifiedAt: row.Modified,
		}
		if vuln, err := p.client.GetVuln(ctx, row.ID); err == nil {
			applyOSVVuln(&entry, vuln)
		}
		entries = append(entries, entry)
	}

	return &FeedResponse{
		Entries:   entries,
		Total:     total,
		FromCache: fromCache,
	}, nil
}

func (p *osvProvider) loadFeedIndex(ctx context.Context) ([]osv.IndexEntry, bool, error) {
	if err := seedIntelCache(p.cfg.CacheDir, "osv"); err != nil {
		return nil, false, err
	}
	cachePath := filepath.Join(p.cfg.CacheDir, "feed", "index.json")
	if cached, err := readOSVFeedIndexCache(cachePath, p.cfg.Feed.CacheTTL); err == nil {
		return cached, true, nil
	}
	if cached, err := readOSVFeedIndexCacheStale(cachePath); err == nil {
		return cached, true, nil
	}

	index, err := osv.StreamModifiedIndex(ctx, osv.ModifiedIndexURLFromEnv(), p.clientUserAgent(), p.cfg.Timeout)
	if err != nil {
		if cached, readErr := readOSVFeedIndexCacheStale(cachePath); readErr == nil {
			return cached, true, nil
		}
		return nil, false, err
	}

	_ = writeOSVFeedIndexCache(cachePath, index)
	return index, false, nil
}

func (p *osvProvider) clientUserAgent() string {
	return "depx (+https://github.com/projectdiscovery/depx)"
}

func filterOSVIndex(index []osv.IndexEntry, since time.Time, ecosystem string) []osv.IndexEntry {
	out := make([]osv.IndexEntry, 0)
	for _, row := range index {
		if row.Modified.Before(since) {
			continue
		}
		if ecosystem != "" && !matchFeedEco(row.Ecosystem, ecosystem) {
			continue
		}
		out = append(out, row)
	}
	return out
}

func matchFeedEco(indexEco, filter string) bool {
	return normalizeFeedEco(indexEco) == normalizeFeedEco(filter)
}

func normalizeFeedEco(eco string) string {
	switch eco {
	case "pypi":
		return "PyPI"
	case "go", "golang":
		return "Go"
	case "crates", "cargo", "rust":
		return "crates.io"
	case "ruby", "gem", "rubygems":
		return "RubyGems"
	case "npm", "javascript", "js":
		return "npm"
	case "maven", "java":
		return "Maven"
	default:
		return eco
	}
}

func applyOSVVuln(entry *source.PackageEntry, vuln *osv.Vulnerability) {
	entry.Summary = vuln.Summary
	entry.Aliases = vuln.Aliases
	entry.Withdrawn = vuln.Withdrawn != ""
	entry.Published = vuln.PublishedTime()
	entry.ImportedAt = vuln.ImportedTime()
	entry.Campaign = vuln.CampaignName()
	if name := vuln.PackageName(); name != "" {
		entry.Name = name
	}
	if eco := vuln.PackageEcosystem(); eco != "" && entry.Ecosystem == "" {
		entry.Ecosystem = eco
	}
	for _, aff := range vuln.Affected {
		if len(aff.Versions) == 1 && entry.Version == "" {
			entry.Version = aff.Versions[0]
			break
		}
	}
	if entry.Name != "" && entry.Ecosystem != "" {
		entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
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
	idx, err := p.LoadMaliciousIndex(ctx, nil, nil)
	if err != nil {
		return nil, err
	}
	hits := idx.Search(req.Query, req.Ecosystem, req.Limit)
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
			if vuln, err := p.client.GetVuln(ctx, hit.IDs[0]); err == nil {
				applyOSVVuln(&entry, vuln)
			}
		}
		if entry.Name != "" && entry.Ecosystem != "" && entry.PackageURL == "" {
			entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
		}
		entries = append(entries, entry)
	}
	return &SearchResponse{
		Entries: entries,
		Total:   len(entries),
	}, nil
}
