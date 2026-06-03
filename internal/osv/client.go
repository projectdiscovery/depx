package osv

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

const (
	DefaultBaseURL   = "https://api.osv.dev/v1"
	ModifiedIndexURL = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
	// MaxVulnResponseBytes caps decoded OSV JSON payloads.
	MaxVulnResponseBytes = 16 << 20
)

func BaseURLFromEnv() string {
	if v := os.Getenv("DEPX_OSV_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return DefaultBaseURL
}

func ModifiedIndexURLFromEnv() string {
	if v := os.Getenv("DEPX_MODIFIED_INDEX_URL"); v != "" {
		return v
	}
	return ModifiedIndexURL
}

type Client struct {
	baseURL     string
	httpClient  *retryablehttp.Client
	userAgent   string
	cacheDir    string
	cacheTTL    time.Duration
	bypassCache bool
}

type ClientOption func(*Client)

func WithBaseURL(url string) ClientOption {
	return func(c *Client) { c.baseURL = strings.TrimRight(url, "/") }
}

func WithCache(dir string, ttl time.Duration) ClientOption {
	return func(c *Client) {
		c.cacheDir = dir
		c.cacheTTL = ttl
	}
}

func WithUserAgent(userAgent string) ClientOption {
	return func(c *Client) {
		if userAgent != "" {
			c.userAgent = userAgent
		}
	}
}

func (c *Client) SetBypassCache(bypass bool) {
	c.bypassCache = bypass
}

func NewClient(version string, timeout time.Duration, opts ...ClientOption) *Client {
	httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	httpClient.HTTPClient.Timeout = timeout

	c := &Client{
		baseURL:    BaseURLFromEnv(),
		httpClient: httpClient,
		userAgent:  fmt.Sprintf("depx/%s (+https://github.com/projectdiscovery/depx)", version),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type Vulnerability struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Modified         string           `json:"modified"`
	Published        string           `json:"published"`
	Withdrawn        string           `json:"withdrawn"`
	Aliases          []string         `json:"aliases"`
	Affected         []Affected       `json:"affected"`
	References       []Reference      `json:"references"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Affected struct {
	Package  *Package `json:"package"`
	Versions []string `json:"versions"`
	Ranges   []Range  `json:"ranges"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type QueryRequest struct {
	Package *PackageQuery `json:"package,omitempty"`
	Version string        `json:"version,omitempty"`
}

type PackageQuery struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns"`
}

type BatchQueryRequest struct {
	Queries []QueryRequest `json:"queries"`
}

type BatchQueryResponse struct {
	Results []QueryResponse `json:"results"`
}

type IndexEntry struct {
	Modified  time.Time
	Ecosystem string
	ID        string
}

func (c *Client) GetVuln(ctx context.Context, id string) (*Vulnerability, error) {
	if vuln, ok := c.getCachedVuln(id); ok {
		return vuln, nil
	}

	vuln, err := c.fetchVuln(ctx, id)
	if err != nil {
		return nil, err
	}
	c.writeCachedVuln(id, vuln)
	return vuln, nil
}

// GetVulnCachedOnly returns a vulnerability from the on-disk cache without
// making network requests. Expired entries are still returned (stale-while-
// revalidate) so feed rendering stays instant.
func (c *Client) GetVulnCachedOnly(id string) (*Vulnerability, bool) {
	if vuln, ok := c.getCachedVuln(id); ok {
		return vuln, true
	}
	return c.getCachedVulnStale(id)
}

func (c *Client) fetchVuln(ctx context.Context, id string) (*Vulnerability, error) {
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("vulnerability %q not found", id)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("osv get vuln: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var vuln Vulnerability
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxVulnResponseBytes)).Decode(&vuln); err != nil {
		return nil, err
	}
	return &vuln, nil
}

func (c *Client) Query(ctx context.Context, q QueryRequest) (*QueryResponse, error) {
	if resp, ok := c.getCachedQuery(q); ok {
		return resp, nil
	}
	resp, err := c.fetchQuery(ctx, q)
	if err != nil {
		return nil, err
	}
	c.writeCachedQuery(q, resp)
	return resp, nil
}

func (c *Client) fetchQuery(ctx context.Context, q QueryRequest) (*QueryResponse, error) {
	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/query", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("osv query: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out QueryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxVulnResponseBytes)).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) QueryBatch(ctx context.Context, queries []QueryRequest) (*BatchQueryResponse, error) {
	results := make([]QueryResponse, len(queries))
	uncachedIdx := make([]int, 0)
	uncachedQueries := make([]QueryRequest, 0, len(queries))

	for i, q := range queries {
		if resp, ok := c.getCachedQuery(q); ok {
			results[i] = *resp
			continue
		}
		uncachedIdx = append(uncachedIdx, i)
		uncachedQueries = append(uncachedQueries, q)
	}

	if len(uncachedQueries) > 0 {
		fetched, err := c.fetchQueryBatch(ctx, uncachedQueries)
		if err != nil {
			return nil, err
		}
		for j, idx := range uncachedIdx {
			results[idx] = fetched.Results[j]
			c.writeCachedQuery(uncachedQueries[j], &results[idx])
		}
	}

	return &BatchQueryResponse{Results: results}, nil
}

func (c *Client) fetchQueryBatch(ctx context.Context, queries []QueryRequest) (*BatchQueryResponse, error) {
	body, err := json.Marshal(BatchQueryRequest{Queries: queries})
	if err != nil {
		return nil, err
	}
	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/querybatch", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("osv querybatch: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out BatchQueryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxVulnResponseBytes)).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func StreamModifiedIndex(ctx context.Context, url string, userAgent string, timeout time.Duration) ([]IndexEntry, error) {
	if url == "" {
		url = ModifiedIndexURL
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("modified index: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	return ParseModifiedIndexBytes(body)
}

// ParseModifiedIndexBytes parses OSV modified_id.csv content.
func ParseModifiedIndexBytes(body []byte) ([]IndexEntry, error) {
	var entries []IndexEntry
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		entry, ok := parseModifiedLine(line)
		if !ok || !strings.HasPrefix(entry.ID, "MAL-") {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func parseModifiedLine(line string) (IndexEntry, bool) {
	comma := strings.Index(line, ",")
	if comma <= 0 {
		return IndexEntry{}, false
	}
	modifiedRaw := line[:comma]
	path := line[comma+1:]
	modified, err := time.Parse(time.RFC3339, strings.TrimSpace(modifiedRaw))
	if err != nil {
		modified, err = time.Parse(time.RFC3339Nano, strings.TrimSpace(modifiedRaw))
		if err != nil {
			return IndexEntry{}, false
		}
	}
	slash := strings.LastIndex(path, "/")
	if slash < 0 {
		return IndexEntry{}, false
	}
	return IndexEntry{
		Modified:  modified.UTC(),
		Ecosystem: path[:slash],
		ID:        path[slash+1:],
	}, true
}

func IsMaliciousID(id string) bool {
	id = strings.TrimSpace(id)
	return strings.HasPrefix(id, "MAL-") || strings.HasPrefix(id, "GHSCAN-MAL-")
}

func MaliciousVulns(vulns []Vulnerability) []Vulnerability {
	out := make([]Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if IsMaliciousID(v.ID) {
			out = append(out, v)
		}
	}
	return out
}
