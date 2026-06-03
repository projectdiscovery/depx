package feed

import (
	"context"
	"time"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/source"
	"github.com/projectdiscovery/depx/internal/sync"
)

type Service struct {
	cfg   *config.Config
	intel intel.Provider
}

func NewService(cfg *config.Config, provider intel.Provider) *Service {
	return &Service{cfg: cfg, intel: provider}
}

type Options struct {
	Since     time.Duration
	Ecosystem string
	Limit     int
}

type Result struct {
	Since     string                `json:"since"`
	Ecosystem string                `json:"ecosystem,omitempty"`
	Limit     int                   `json:"limit"`
	Total     int                   `json:"total"`
	Shown     int                   `json:"shown"`
	Window    source.WindowStats    `json:"window"`
	Corpus    source.CorpusStats    `json:"corpus,omitempty"`
	Packages  []source.PackageEntry `json:"packages"`
	FromCache bool                  `json:"-"`
	Source    string                `json:"source,omitempty"`
}

func (s *Service) List(ctx context.Context, opts Options) (*Result, error) {
	if opts.Since == 0 {
		opts.Since = s.cfg.Feed.Since
	}
	if opts.Limit == 0 {
		opts.Limit = s.cfg.Feed.Limit
	}

	resp, err := s.intel.Feed(ctx, intel.FeedRequest{
		Since:     opts.Since,
		Ecosystem: opts.Ecosystem,
		Limit:     opts.Limit,
		CacheDir:  s.cfg.CacheDir,
		CacheTTL:  s.cfg.Feed.CacheTTL,
		Timeout:   s.cfg.Timeout,
	})
	if err != nil {
		return nil, apperr.Upstream("load feed", err)
	}

	return &Result{
		Since:     intel.FormatSince(opts.Since),
		Ecosystem: opts.Ecosystem,
		Limit:     opts.Limit,
		Total:     resp.Total,
		Shown:     len(resp.Entries),
		Window:    resp.WindowStats,
		Corpus:    corpusStats(s.intel.SyncStatus()),
		Packages:  resp.Entries,
		FromCache: resp.FromCache,
		Source:    s.intel.Name(),
	}, nil
}

func corpusStats(st sync.Status) source.CorpusStats {
	out := source.CorpusStats{
		Source:          st.Source,
		IndexedPackages: st.Packages,
		PendingSync:     st.Pending,
	}
	if !st.LastSuccess.IsZero() {
		out.LastSync = st.LastSuccess.UTC().Format(time.RFC3339)
	}
	return out
}
