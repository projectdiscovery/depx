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
	"github.com/projectdiscovery/depx/internal/pd"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/source"
	syncengine "github.com/projectdiscovery/depx/internal/sync"
)

type pdProvider struct {
	client  *pd.Client
	cfg     *config.Config
	engine  *syncengine.Engine
	version string

	feedRefreshMu  sync.Mutex
	feedRefreshing bool
}

func NewPD(version string, cfg *config.Config) (Provider, error) {
	client, err := pd.NewClient(fmt.Sprintf("depx/%s (+https://github.com/projectdiscovery/depx)", version), cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &pdProvider{
		client:  client,
		cfg:     cfg,
		engine:  newSyncEngine(version, cfg),
		version: version,
	}, nil
}

func (p *pdProvider) Name() string { return "pd" }

func (p *pdProvider) StartBackgroundSync(ctx context.Context) {
	p.engine.StartBackground(ctx)
}

func (p *pdProvider) SyncStatus() syncengine.Status {
	return p.engine.StatusSnapshot()
}

func (p *pdProvider) GetVuln(ctx context.Context, id string) (*osv.Vulnerability, error) {
	raw, err := p.client.GetVuln(ctx, id)
	if err != nil {
		return nil, err
	}
	var vuln osv.Vulnerability
	if err := json.Unmarshal(raw, &vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

func (p *pdProvider) Query(ctx context.Context, q osv.QueryRequest) (*osv.QueryResponse, error) {
	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	raw, err := p.client.Query(ctx, body)
	if err != nil {
		return nil, err
	}
	var out osv.QueryResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (p *pdProvider) QueryBatch(ctx context.Context, queries []osv.QueryRequest) (*osv.BatchQueryResponse, error) {
	body, err := json.Marshal(osv.BatchQueryRequest{Queries: queries})
	if err != nil {
		return nil, err
	}
	raw, err := p.client.QueryBatch(ctx, body)
	if err != nil {
		return nil, err
	}
	var out osv.BatchQueryResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (p *pdProvider) VulnPageURL(id string) string {
	if pkg, err := p.client.GetPackage(context.Background(), id); err == nil {
		if pkg.OSVURL != "" {
			return pkg.OSVURL
		}
	}
	if osv.IsMaliciousID(id) && len(id) > 4 && id[:4] == "MAL-" {
		return osv.VulnPageURL(id)
	}
	return pd.APIURL() + "/github/malicious/packages/" + id
}

func (p *pdProvider) Feed(ctx context.Context, req FeedRequest) (*FeedResponse, error) {
	if req.Since == 0 {
		req.Since = p.cfg.Feed.Since
	}
	if req.Limit == 0 {
		req.Limit = p.cfg.Feed.Limit
	}

	cachePath := pdFeedCachePath(p.cfg.CacheDir)
	if cached, err := readPDFeedCache(cachePath, p.cfg.Feed.CacheTTL, req); err == nil {
		return cached, nil
	}
	if cached, err := readPDFeedCacheStale(cachePath, req); err == nil {
		p.schedulePDFeedRefresh(req)
		cached.FromCache = true
		return cached, nil
	}

	resp, err := p.fetchPDFeedLive(ctx, req)
	if err != nil {
		return nil, err
	}
	_ = writePDFeedCache(cachePath, req, resp)
	return resp, nil
}

func (p *pdProvider) fetchPDFeedLive(ctx context.Context, req FeedRequest) (*FeedResponse, error) {
	sinceTime := time.Now().UTC().Add(-req.Since)
	perPage := req.Limit
	if perPage <= 0 || perPage > 1000 {
		perPage = 100
	}
	if perPage < req.Limit && req.Limit <= 1000 {
		perPage = req.Limit
	}

	var collected []source.PackageEntry
	inWindow := 0
	page := 1

	for {
		res, err := p.client.ListPackagesEnvelope(ctx, pd.ListPackagesParams{
			Page:      page,
			PerPage:   perPage,
			Ecosystem: req.Ecosystem,
			Withdrawn: "exclude",
		})
		if err != nil {
			return nil, err
		}
		if len(res.Packages) == 0 {
			break
		}

		allOlder := true
		for _, pkg := range res.Packages {
			if pkg.Published.IsZero() || pkg.Published.Before(sinceTime) {
				continue
			}
			allOlder = false
			inWindow++
			if req.Ecosystem != "" && !matchFeedEco(pkg.Ecosystem, req.Ecosystem) {
				continue
			}
			collected = append(collected, entryFromPDPackage(pkg))
		}

		if allOlder {
			break
		}
		if res.Meta.TotalPages > 0 && page >= res.Meta.TotalPages {
			break
		}
		page++
	}

	source.SortPackageEntriesByPublished(collected)
	windowStats := source.ComputeWindowStats(collected)
	limit := req.Limit
	if limit <= 0 || limit > len(collected) {
		limit = len(collected)
	}

	return &FeedResponse{
		Entries:     collected[:limit],
		WindowStats: windowStats,
		Total:       inWindow,
		FromCache:   false,
	}, nil
}

func (p *pdProvider) schedulePDFeedRefresh(req FeedRequest) {
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
		resp, err := p.fetchPDFeedLive(ctx, req)
		if err != nil {
			return
		}
		cachePath := pdFeedCachePath(p.cfg.CacheDir)
		_ = writePDFeedCache(cachePath, req, resp)
	}()
}

type cachedPDFeed struct {
	FetchedAt time.Time    `json:"fetched_at"`
	Since     string       `json:"since"`
	Ecosystem string       `json:"ecosystem,omitempty"`
	Limit     int          `json:"limit"`
	Response  FeedResponse `json:"response"`
}

func pdFeedCachePath(cacheDir string) string {
	return filepath.Join(cacheDir, "feed", "pd.json")
}

func pdFeedCacheKey(req FeedRequest) (since string, limit int) {
	since = FormatSince(req.Since)
	limit = req.Limit
	return since, limit
}

func readPDFeedCache(path string, ttl time.Duration, req FeedRequest) (*FeedResponse, error) {
	resp, err := readPDFeedCacheFile(path)
	if err != nil {
		return nil, err
	}
	if time.Since(resp.fetchedAt) > ttl {
		return nil, fmt.Errorf("cache expired")
	}
	sinceKey, limitKey := pdFeedCacheKey(req)
	if resp.since != sinceKey || resp.ecosystem != req.Ecosystem || resp.limit != limitKey {
		return nil, fmt.Errorf("cache miss")
	}
	out := resp.response
	return &out, nil
}

func readPDFeedCacheStale(path string, req FeedRequest) (*FeedResponse, error) {
	resp, err := readPDFeedCacheFile(path)
	if err != nil {
		return nil, err
	}
	sinceKey, limitKey := pdFeedCacheKey(req)
	if resp.since != sinceKey || resp.ecosystem != req.Ecosystem || resp.limit != limitKey {
		return nil, fmt.Errorf("cache miss")
	}
	out := resp.response
	return &out, nil
}

type pdFeedCacheRecord struct {
	fetchedAt time.Time
	since     string
	ecosystem string
	limit     int
	response  FeedResponse
}

func readPDFeedCacheFile(path string) (*pdFeedCacheRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cached cachedPDFeed
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, err
	}
	return &pdFeedCacheRecord{
		fetchedAt: cached.FetchedAt,
		since:     cached.Since,
		ecosystem: cached.Ecosystem,
		limit:     cached.Limit,
		response:  cached.Response,
	}, nil
}

func writePDFeedCache(path string, req FeedRequest, resp *FeedResponse) error {
	if resp == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	sinceKey, limitKey := pdFeedCacheKey(req)
	payload, err := json.Marshal(cachedPDFeed{
		FetchedAt: time.Now().UTC(),
		Since:     sinceKey,
		Ecosystem: req.Ecosystem,
		Limit:     limitKey,
		Response:  *resp,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}

func (p *pdProvider) LoadMaliciousIndex(ctx context.Context, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	return p.engine.LoadIndex(ctx, onProgress, onStatus)
}

func entryFromPDPackage(pkg pd.Package) source.PackageEntry {
	entry := source.PackageEntry{
		Ecosystem:  pkg.Ecosystem,
		Name:       pkg.PkgName,
		IDs:        []string{pkg.MalID},
		Summary:    pkg.Summary,
		ModifiedAt: pkg.Modified,
		Published:  pkg.Published,
		Withdrawn:  pkg.Withdrawn != "",
		Aliases:    append([]string(nil), pkg.Aliases...),
		Campaign:   pkg.Source,
	}
	if len(pkg.AffectedVersions) == 1 {
		entry.Version = pkg.AffectedVersions[0]
	}
	if entry.Name != "" && entry.Ecosystem != "" {
		entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
	}
	return entry
}

func (p *pdProvider) Search(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	if req.Limit <= 0 {
		req.Limit = p.cfg.Feed.Limit
	}
	// PD list API q= is exact package name only; substring search uses the local index.
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
		if len(hit.IDs) > 0 {
			if pkg, err := p.client.GetPackage(ctx, hit.IDs[0]); err == nil {
				entry = entryFromPDPackage(*pkg)
			}
		}
		if entry.Name != "" && entry.Ecosystem != "" && entry.PackageURL == "" {
			entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
		}
		entries = append(entries, entry)
	}
	return &SearchResponse{
		Entries: entries,
		Total:   match.Total,
	}, nil
}
