package intel

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/pd"
	"github.com/projectdiscovery/depx/internal/source"
	"github.com/projectdiscovery/depx/internal/sync"
)

// Provider is the malicious-package intelligence backend (OSV or PD).
type Provider interface {
	Name() string

	GetVuln(ctx context.Context, id string) (*osv.Vulnerability, error)
	Query(ctx context.Context, q osv.QueryRequest) (*osv.QueryResponse, error)
	QueryBatch(ctx context.Context, queries []osv.QueryRequest) (*osv.BatchQueryResponse, error)

	Feed(ctx context.Context, req FeedRequest) (*FeedResponse, error)
	Search(ctx context.Context, req SearchRequest) (*SearchResponse, error)
	LoadMaliciousIndex(ctx context.Context, onProgress osv.IndexLoadProgress, onStatus osv.IndexLoadStatus) (*osv.MaliciousIndex, error)

	VulnPageURL(id string) string

	StartBackgroundSync(ctx context.Context)
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
	Entries   []source.PackageEntry
	Total     int
	FromCache bool
}

type SearchRequest struct {
	Query     string
	Ecosystem string
	Limit     int
}

type SearchResponse struct {
	Entries []source.PackageEntry
	Total   int
}

func New(version string, cfg *config.Config) (Provider, error) {
	if pd.Enabled() {
		return NewPD(version, cfg)
	}
	return NewOSV(version, cfg), nil
}

func NewFromClient(version string, cfg *config.Config) (Provider, error) {
	return New(version, cfg)
}

func MaliciousVulns(vulns []osv.Vulnerability) []osv.Vulnerability {
	return osv.MaliciousVulns(vulns)
}

func IsMaliciousID(id string) bool {
	return osv.IsMaliciousID(id)
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
