package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/pd"
	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/source"
	"github.com/projectdiscovery/depx/internal/sync"
)

type pdProvider struct {
	client *pd.Client
	cfg    *config.Config
	engine *sync.Engine
}

func NewPD(version string, cfg *config.Config) (Provider, error) {
	client, err := pd.NewClient(fmt.Sprintf("depx/%s (+https://github.com/projectdiscovery/depx)", version), cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return &pdProvider{
		client: client,
		cfg:    cfg,
		engine: newSyncEngine(version, cfg),
	}, nil
}

func (p *pdProvider) Name() string { return "pd" }

func (p *pdProvider) StartBackgroundSync(ctx context.Context) {
	p.engine.StartBackground(ctx)
}

func (p *pdProvider) SyncStatus() sync.Status {
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
			if pkg.Modified.Before(sinceTime) {
				continue
			}
			allOlder = false
			inWindow++
			if req.Ecosystem != "" && !matchFeedEco(pkg.Ecosystem, req.Ecosystem) {
				continue
			}
			if len(collected) < req.Limit {
				collected = append(collected, entryFromPDPackage(pkg))
			}
		}

		if allOlder || len(collected) >= req.Limit {
			break
		}
		if res.Meta.TotalPages > 0 && page >= res.Meta.TotalPages {
			break
		}
		page++
	}

	return &FeedResponse{
		Entries:   collected,
		Total:     inWindow,
		FromCache: false,
	}, nil
}

func (p *pdProvider) LoadMaliciousIndex(ctx context.Context, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	if err := seedIntelCache(p.cfg.CacheDir, "pd"); err != nil {
		return nil, err
	}
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
		Total:   len(entries),
	}, nil
}
