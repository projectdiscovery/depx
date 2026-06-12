package intel

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/malindex"
	"github.com/projectdiscovery/depx/internal/source"
	"github.com/projectdiscovery/depx/internal/sync"
)

// Provider is the malicious-package intelligence backend. depx has a single
// source — the ProjectDiscovery inventory export — served entirely from a
// local compiled index after the first download.
type Provider interface {
	Name() string

	GetVuln(ctx context.Context, id string) (*malindex.Vulnerability, error)
	Query(ctx context.Context, q malindex.QueryRequest) (*malindex.QueryResponse, error)
	QueryBatch(ctx context.Context, queries []malindex.QueryRequest) (*malindex.BatchQueryResponse, error)

	Feed(ctx context.Context, req FeedRequest) (*FeedResponse, error)
	Search(ctx context.Context, req SearchRequest) (*SearchResponse, error)
	LoadMaliciousIndex(ctx context.Context, onProgress malindex.IndexLoadProgress, onStatus malindex.IndexLoadStatus) (*malindex.MaliciousIndex, error)

	VulnPageURL(id string) string

	StartBackgroundSync(ctx context.Context)
	// WaitBackgroundSync blocks until any in-flight background refresh finishes
	// so it persists before the process exits. Bounded by the network timeout.
	WaitBackgroundSync()
	SyncStatus() sync.Status
}

type FeedRequest struct {
	Since     time.Duration
	Ecosystem string
	Limit     int
	CacheDir  string
	CacheTTL  time.Duration
	Timeout   time.Duration
}

type FeedResponse struct {
	Entries     []source.PackageEntry
	WindowStats source.WindowStats
	Total       int
	FromCache   bool
}

type SearchRequest struct {
	Query      string
	Ecosystem  string
	Limit      int
	OnProgress malindex.IndexLoadProgress
	OnStatus   malindex.IndexLoadStatus
}

type SearchResponse struct {
	Entries []source.PackageEntry
	Total   int
}

// New constructs the inventory-backed intelligence provider.
func New(version string, cfg *config.Config) (Provider, error) {
	return newProvider(version, cfg), nil
}

func NewFromClient(version string, cfg *config.Config) (Provider, error) {
	return New(version, cfg)
}

func MaliciousVulns(vulns []malindex.Vulnerability) []malindex.Vulnerability {
	return malindex.MaliciousVulns(vulns)
}

func IsMaliciousID(id string) bool {
	return malindex.IsMaliciousID(id)
}

func FormatSince(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		days := int(d / (24 * time.Hour))
		return fmt.Sprintf("%dd", days)
	}
	if d%time.Hour == 0 {
		hours := int(d / time.Hour)
		return fmt.Sprintf("%dh", hours)
	}
	return d.String()
}
