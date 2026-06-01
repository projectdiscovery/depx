package source

import (
	"context"
	"time"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/osv"
)

type FeedOpts struct {
	Since     time.Time
	Ecosystem string
	Limit     int
	Live      bool
}

type PackageEntry struct {
	Ecosystem  string    `json:"ecosystem"`
	Name       string    `json:"name"`
	Version    string    `json:"version,omitempty"`
	PackageURL string    `json:"registry_url,omitempty"`
	IDs        []string  `json:"ids"`
	Aliases    []string  `json:"aliases,omitempty"`
	ModifiedAt time.Time `json:"modified_at"`
	Published  time.Time `json:"published_at,omitempty"`
	ImportedAt time.Time `json:"imported_at,omitempty"`
	Campaign   string    `json:"campaign,omitempty"`
	Summary    string    `json:"summary,omitempty"`
	Withdrawn  bool      `json:"withdrawn"`
}

type FeedSource interface {
	Name() string
	FetchFeed(ctx context.Context, opts FeedOpts) ([]PackageEntry, error)
}

type PDFeedSource struct{}

func (PDFeedSource) Name() string { return "pd" }

func (PDFeedSource) FetchFeed(context.Context, FeedOpts) ([]PackageEntry, error) {
	return nil, apperr.ErrNotConfig
}

type OSVFeedSource struct {
	Index []osv.IndexEntry
}

func (s OSVFeedSource) Name() string { return "osv" }

func (s OSVFeedSource) FetchFeed(_ context.Context, opts FeedOpts) ([]PackageEntry, error) {
	entries := make([]PackageEntry, 0, opts.Limit)
	for _, row := range s.Index {
		if !row.Modified.After(opts.Since) && !row.Modified.Equal(opts.Since) {
			continue
		}
		if opts.Ecosystem != "" && !matchEcosystem(row.Ecosystem, opts.Ecosystem) {
			continue
		}
		entries = append(entries, PackageEntry{
			Ecosystem:  row.Ecosystem,
			IDs:        []string{row.ID},
			ModifiedAt: row.Modified,
			Campaign:   "",
		})
		if opts.Limit > 0 && len(entries) >= opts.Limit {
			break
		}
	}
	return entries, nil
}

func matchEcosystem(indexEco, filter string) bool {
	indexEco = normalizeEco(indexEco)
	filter = normalizeEco(filter)
	return indexEco == filter
}

func normalizeEco(eco string) string {
	switch eco {
	case "npm", "PyPI", "Go", "crates.io", "RubyGems", "Maven":
		return eco
	default:
		return eco
	}
}

func MergeFeedSources(ctx context.Context, sources []FeedSource, opts FeedOpts) ([]PackageEntry, error) {
	var merged []PackageEntry
	for _, src := range sources {
		items, err := src.FetchFeed(ctx, opts)
		if err != nil {
			if err == apperr.ErrNotConfig {
				continue
			}
			return nil, err
		}
		merged = append(merged, items...)
	}
	return merged, nil
}
