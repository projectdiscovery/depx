package search

import (
	"context"
	"testing"

	"github.com/projectdiscovery/depx/internal/apperr"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/intel/inteltest"
	"github.com/projectdiscovery/depx/internal/source"
)

func TestSearchRequiresQuery(t *testing.T) {
	cfg := config.Default()
	svc := NewService(cfg, &inteltest.Stub{})
	_, err := svc.Run(context.Background(), Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if apperr.ExitCode(err) != apperr.CodeUsage {
		t.Fatalf("exit code = %d, want usage", apperr.ExitCode(err))
	}
}

func TestSearchReturnsTotal(t *testing.T) {
	cfg := config.Default()
	stub := &inteltest.Stub{
		SearchFn: func(_ context.Context, req intel.SearchRequest) (*intel.SearchResponse, error) {
			return &intel.SearchResponse{
				Total: 42,
				Entries: []source.PackageEntry{
					{Ecosystem: "npm", Name: "apkeep", IDs: []string{"MAL-1"}},
				},
			}, nil
		},
	}
	svc := NewService(cfg, stub)
	result, err := svc.Run(context.Background(), Options{Query: "apkeep", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 42 {
		t.Fatalf("total = %d, want 42", result.Total)
	}
	if result.Shown != 1 {
		t.Fatalf("shown = %d, want 1", result.Shown)
	}
}
