package search

import (
	"context"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/source"
)

type Service struct {
	cfg   *config.Config
	intel intel.Provider
}

func NewService(cfg *config.Config, provider intel.Provider) *Service {
	return &Service{cfg: cfg, intel: provider}
}

type Options struct {
	Query     string
	Ecosystem string
	Limit     int
}

type Result struct {
	Query     string                `json:"query"`
	Ecosystem string                `json:"ecosystem,omitempty"`
	Limit     int                   `json:"limit"`
	Total     int                   `json:"total"`
	Packages  []source.PackageEntry `json:"packages"`
	Source    string                `json:"source,omitempty"`
}

func (s *Service) Run(ctx context.Context, opts Options) (*Result, error) {
	query := opts.Query
	if query == "" {
		return nil, apperr.Usage("search query is required")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = s.cfg.Feed.Limit
	}

	resp, err := s.intel.Search(ctx, intel.SearchRequest{
		Query:     query,
		Ecosystem: opts.Ecosystem,
		Limit:     limit,
	})
	if err != nil {
		return nil, apperr.Upstream("search failed", err)
	}

	return &Result{
		Query:     query,
		Ecosystem: opts.Ecosystem,
		Limit:     limit,
		Total:     resp.Total,
		Packages:  resp.Entries,
		Source:    s.intel.Name(),
	}, nil
}
