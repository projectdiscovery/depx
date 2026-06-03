package inteltest

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/sync"
)

// Stub implements intel.Provider for unit tests.
type Stub struct {
	NameVal string

	FeedFn   func(context.Context, intel.FeedRequest) (*intel.FeedResponse, error)
	SearchFn func(context.Context, intel.SearchRequest) (*intel.SearchResponse, error)
	QueryFn  func(context.Context, osv.QueryRequest) (*osv.QueryResponse, error)

	Index *osv.MaliciousIndex
}

func (s *Stub) Name() string {
	if s.NameVal != "" {
		return s.NameVal
	}
	return "stub"
}

func (s *Stub) GetVuln(context.Context, string) (*osv.Vulnerability, error) {
	return nil, fmt.Errorf("vulnerability not found")
}

func (s *Stub) Query(ctx context.Context, q osv.QueryRequest) (*osv.QueryResponse, error) {
	if s.QueryFn != nil {
		return s.QueryFn(ctx, q)
	}
	return &osv.QueryResponse{}, nil
}

func (s *Stub) QueryBatch(context.Context, []osv.QueryRequest) (*osv.BatchQueryResponse, error) {
	return &osv.BatchQueryResponse{}, nil
}

func (s *Stub) Feed(ctx context.Context, req intel.FeedRequest) (*intel.FeedResponse, error) {
	if s.FeedFn != nil {
		return s.FeedFn(ctx, req)
	}
	return &intel.FeedResponse{}, nil
}

func (s *Stub) Search(ctx context.Context, req intel.SearchRequest) (*intel.SearchResponse, error) {
	if s.SearchFn != nil {
		return s.SearchFn(ctx, req)
	}
	return &intel.SearchResponse{}, nil
}

func (s *Stub) LoadMaliciousIndex(context.Context, osv.IndexLoadProgress, osv.IndexLoadStatus) (*osv.MaliciousIndex, error) {
	if s.Index != nil {
		return s.Index, nil
	}
	return &osv.MaliciousIndex{}, nil
}

func (s *Stub) VulnPageURL(id string) string { return "https://osv.dev/vulnerability/" + id }

func (s *Stub) StartBackgroundSync(context.Context) {}

func (s *Stub) SyncStatus() sync.Status { return sync.Status{Source: s.Name()} }
