package feed

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/intel/inteltest"
	"github.com/projectdiscovery/depx/internal/source"
)

func TestFeedListDefaults(t *testing.T) {
	cfg := config.Default()
	stub := &inteltest.Stub{
		NameVal: "stub",
		FeedFn: func(_ context.Context, req intel.FeedRequest) (*intel.FeedResponse, error) {
			if req.Limit != cfg.Feed.Limit {
				t.Fatalf("limit = %d, want default %d", req.Limit, cfg.Feed.Limit)
			}
			return &intel.FeedResponse{
				Total: 3,
				Entries: []source.PackageEntry{
					{Ecosystem: "npm", Name: "pkg-a", IDs: []string{"MAL-1"}},
				},
			}, nil
		},
	}
	svc := NewService(cfg, stub)
	result, err := svc.List(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 3 {
		t.Fatalf("total = %d, want 3", result.Total)
	}
	if result.Shown != 1 {
		t.Fatalf("shown = %d, want 1", result.Shown)
	}
	if result.Source != "stub" {
		t.Fatalf("source = %q", result.Source)
	}
}

func TestFeedListSinceOverride(t *testing.T) {
	cfg := config.Default()
	var gotSince time.Duration
	stub := &inteltest.Stub{
		FeedFn: func(_ context.Context, req intel.FeedRequest) (*intel.FeedResponse, error) {
			gotSince = req.Since
			return &intel.FeedResponse{}, nil
		},
	}
	svc := NewService(cfg, stub)
	since := 48 * time.Hour
	if _, err := svc.List(context.Background(), Options{Since: since}); err != nil {
		t.Fatal(err)
	}
	if gotSince != since {
		t.Fatalf("since = %v, want %v", gotSince, since)
	}
}
