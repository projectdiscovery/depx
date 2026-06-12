package intel

import (
	"context"
	"fmt"
	"strings"
	gosync "sync"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/inventory"
	"github.com/projectdiscovery/depx/internal/malindex"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/source"
	syncengine "github.com/projectdiscovery/depx/internal/sync"
)

// provider serves all intelligence operations from the local inventory index.
type provider struct {
	cfg     *config.Config
	engine  *syncengine.Engine
	version string

	mu  gosync.Mutex
	idx *malindex.MaliciousIndex
}

func newProvider(version string, cfg *config.Config) *provider {
	return &provider{
		cfg:     cfg,
		version: version,
		engine: syncengine.NewEngine(syncengine.Config{
			CacheDir:  cfg.CacheDir,
			UserAgent: providerUserAgent(version),
			Timeout:   cfg.Timeout,
		}),
	}
}

func providerUserAgent(version string) string {
	return fmt.Sprintf("depx/%s (+https://github.com/projectdiscovery/depx)", version)
}

func (p *provider) Name() string { return "pd" }

func (p *provider) StartBackgroundSync(ctx context.Context) { p.engine.StartBackground(ctx) }

func (p *provider) WaitBackgroundSync() { p.engine.Wait() }

func (p *provider) SyncStatus() syncengine.Status {
	st := p.engine.StatusSnapshot()
	// Report the public source label consistently with Name(). The engine uses
	// an internal "inventory" identifier for on-disk storage, but every
	// user-facing surface (JSON "source", corpus.source, verbose status) should
	// show the same name.
	st.Source = p.Name()
	return st
}

func (p *provider) LoadMaliciousIndex(ctx context.Context, onProgress malindex.IndexLoadProgress, onStatus malindex.IndexLoadStatus) (*malindex.MaliciousIndex, error) {
	return p.engine.LoadIndex(ctx, onProgress, onStatus)
}

// index returns a process-cached compiled index. A depx invocation is short
// lived, so loading once per process is sufficient and keeps GetVuln/Query
// fully in-memory.
func (p *provider) index(ctx context.Context) (*malindex.MaliciousIndex, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.idx != nil {
		return p.idx, nil
	}
	idx, err := p.engine.LoadIndex(ctx, nil, nil)
	if err != nil {
		return nil, err
	}
	p.idx = idx
	return idx, nil
}

func (p *provider) GetVuln(ctx context.Context, id string) (*malindex.Vulnerability, error) {
	idx, err := p.index(ctx)
	if err != nil {
		return nil, err
	}
	if v, ok := idx.Vuln(id); ok {
		return v, nil
	}
	return nil, fmt.Errorf("advisory %q not found", id)
}

func (p *provider) Query(ctx context.Context, q malindex.QueryRequest) (*malindex.QueryResponse, error) {
	idx, err := p.index(ctx)
	if err != nil {
		return nil, err
	}
	name, eco := queryTarget(q)
	return &malindex.QueryResponse{Vulns: derefVulns(idx.QueryLocal(eco, name, q.Version))}, nil
}

func (p *provider) QueryBatch(ctx context.Context, queries []malindex.QueryRequest) (*malindex.BatchQueryResponse, error) {
	idx, err := p.index(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]malindex.QueryResponse, len(queries))
	for i, q := range queries {
		name, eco := queryTarget(q)
		results[i] = malindex.QueryResponse{Vulns: derefVulns(idx.QueryLocal(eco, name, q.Version))}
	}
	return &malindex.BatchQueryResponse{Results: results}, nil
}

func queryTarget(q malindex.QueryRequest) (name, ecosystem string) {
	if q.Package != nil {
		return q.Package.Name, q.Package.Ecosystem
	}
	return "", ""
}

func derefVulns(in []*malindex.Vulnerability) []malindex.Vulnerability {
	out := make([]malindex.Vulnerability, 0, len(in))
	for _, v := range in {
		if v != nil {
			out = append(out, *v)
		}
	}
	return out
}

func (p *provider) VulnPageURL(id string) string {
	if strings.HasPrefix(id, "MAL-") {
		return malindex.VulnPageURL(id)
	}
	return inventory.PackagePageURL(id)
}

func (p *provider) Feed(ctx context.Context, req FeedRequest) (*FeedResponse, error) {
	if req.Since == 0 {
		req.Since = p.cfg.Feed.Since
	}
	if req.Limit == 0 {
		req.Limit = p.cfg.Feed.Limit
	}
	idx, err := p.LoadMaliciousIndex(ctx, nil, nil)
	if err != nil {
		return nil, err
	}
	sinceTime := time.Now().UTC().Add(-req.Since)
	hits := idx.ListSincePublished(sinceTime, req.Ecosystem)

	entries := make([]source.PackageEntry, 0, len(hits))
	for _, h := range hits {
		entries = append(entries, p.entryFromHit(h))
	}
	source.SortPackageEntriesByPublished(entries)
	total := len(entries)
	windowStats := source.ComputeWindowStats(entries)

	limit := req.Limit
	if limit <= 0 || limit > len(entries) {
		limit = len(entries)
	}
	return &FeedResponse{
		Entries:     entries[:limit],
		WindowStats: windowStats,
		Total:       total,
	}, nil
}

func (p *provider) Search(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	if req.Limit <= 0 {
		req.Limit = p.cfg.Feed.Limit
	}
	idx, err := p.LoadMaliciousIndex(ctx, req.OnProgress, req.OnStatus)
	if err != nil {
		return nil, err
	}
	match := idx.Search(req.Query, req.Ecosystem, req.Limit)
	entries := make([]source.PackageEntry, 0, len(match.Hits))
	for _, h := range match.Hits {
		entries = append(entries, p.entryFromHit(h))
	}
	return &SearchResponse{Entries: entries, Total: match.Total}, nil
}

func (p *provider) entryFromHit(h malindex.SearchHit) source.PackageEntry {
	entry := source.PackageEntry{
		Ecosystem:  h.Ecosystem,
		Name:       h.Name,
		IDs:        append([]string(nil), h.IDs...),
		Aliases:    append([]string(nil), h.Aliases...),
		Summary:    h.Summary,
		Published:  h.Published,
		ModifiedAt: h.Modified,
		ImportedAt: h.Imported,
	}
	if entry.Name != "" && entry.Ecosystem != "" {
		entry.PackageURL = registry.PackagePageURL(entry.Ecosystem, entry.Name)
		entry.Quarantined = registry.IsQuarantinedCached(p.cfg.CacheDir, entry.Ecosystem, entry.Name)
	}
	return entry
}
