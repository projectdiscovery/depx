package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultAPIBase   = "https://api.github.com"
	defaultPollEvery = 2 * time.Second
	defaultSBOMTTL   = 24 * time.Hour
)

// Client fetches dependency-graph SBOM exports from GitHub.
type Client struct {
	HTTPClient *http.Client
	APIBase    string
	Token      string
	UserAgent  string
	CacheTTL   time.Duration
	PollEvery  time.Duration
}

type FetchOptions struct {
	CacheDir string
	OnStatus func(string)
}

func NewClient(userAgent, token string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		HTTPClient: &http.Client{Timeout: timeout},
		APIBase:    APIBaseFromEnv(),
		Token:      strings.TrimSpace(token),
		UserAgent:  userAgent,
		CacheTTL:   defaultSBOMTTL,
		PollEvery:  defaultPollEvery,
	}
}

func APIBaseFromEnv() string {
	if v := strings.TrimSpace(os.Getenv("DEPX_GITHUB_API_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return defaultAPIBase
}

func TokenFromEnv() string {
	if v := strings.TrimSpace(os.Getenv("DEPX_GITHUB_TOKEN")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("GH_TOKEN"))
}

// FetchSBOM returns a cached or freshly downloaded SPDX JSON path for the repo.
func (c *Client) FetchSBOM(ctx context.Context, repo Repo, opts FetchOptions) (string, error) {
	if opts.CacheDir == "" {
		return "", fmt.Errorf("github cache directory is required")
	}
	cachePath := repo.CachePath(opts.CacheDir)
	if body, ok := readFreshCache(cachePath, c.CacheTTL); ok {
		status(opts, fmt.Sprintf("Using cached SBOM for %s", repo))
		_ = body
		return cachePath, nil
	}

	status(opts, fmt.Sprintf("Fetching SBOM from GitHub for %s…", repo))
	body, err := c.downloadSBOM(ctx, repo, opts)
	if err != nil {
		return "", err
	}
	normalized, err := normalizeSBOMJSON(body)
	if err != nil {
		return "", err
	}
	if err := writeCache(cachePath, normalized); err != nil {
		return "", err
	}
	status(opts, fmt.Sprintf("SBOM ready for %s", repo))
	return cachePath, nil
}

func (c *Client) downloadSBOM(ctx context.Context, repo Repo, opts FetchOptions) ([]byte, error) {
	if body, err := c.fetchSyncSBOM(ctx, repo); err == nil {
		return body, nil
	} else if !shouldTryAsync(err) {
		return nil, err
	}
	return c.fetchAsyncSBOM(ctx, repo, opts)
}

func (c *Client) fetchSyncSBOM(ctx context.Context, repo Repo) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/dependency-graph/sbom", c.APIBase, repo.Owner, repo.Name)
	return c.getBody(ctx, endpoint, http.StatusOK)
}

func (c *Client) fetchAsyncSBOM(ctx context.Context, repo Repo, opts FetchOptions) ([]byte, error) {
	generate := fmt.Sprintf("%s/repos/%s/%s/dependency-graph/sbom/generate-report", c.APIBase, repo.Owner, repo.Name)
	body, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, generate, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusCreated && statusCode != http.StatusOK {
		return nil, newAPIError(generate, statusCode, body, hdr)
	}

	var resp struct {
		SBOMURL string `json:"sbom_url"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("github sbom generate: invalid response")
	}
	uuid, err := uuidFromSBOMURL(resp.SBOMURL)
	if err != nil {
		return nil, err
	}

	fetchURL := fmt.Sprintf("%s/repos/%s/%s/dependency-graph/sbom/fetch-report/%s", c.APIBase, repo.Owner, repo.Name, uuid)
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("github sbom generation timed out for %s", repo)
		}

		body, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, fetchURL, nil)
		if err != nil {
			return nil, err
		}

		switch statusCode {
		case http.StatusOK:
			return body, nil
		case http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			if loc := hdr.Get("Location"); loc != "" {
				return c.getBody(ctx, loc, http.StatusOK)
			}
			if len(body) > 0 {
				return body, nil
			}
			return nil, newAPIError(fetchURL, statusCode, body, hdr)
		case http.StatusAccepted, http.StatusCreated:
			status(opts, fmt.Sprintf("Waiting for GitHub SBOM (%s)…", repo))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.pollEvery()):
				continue
			}
		default:
			return nil, newAPIError(fetchURL, statusCode, body, nil)
		}
	}
}

func uuidFromSBOMURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("github sbom generate: missing sbom_url")
	}
	parts := strings.Split(strings.Trim(raw, "/"), "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("github sbom generate: invalid sbom_url")
	}
	return parts[len(parts)-1], nil
}

func (c *Client) getBody(ctx context.Context, endpoint string, wantStatus int) ([]byte, error) {
	raw, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != wantStatus {
		return nil, newAPIError(endpoint, statusCode, raw, hdr)
	}
	return raw, nil
}

func (c *Client) doRequest(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, int, error) {
	raw, status, _, err := c.doRequestWithHeaders(ctx, method, endpoint, body)
	return raw, status, err
}

func (c *Client) doRequestWithHeaders(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, int, http.Header, error) {
	for attempt := 0; attempt <= maxRateLimitRetries; attempt++ {
		raw, status, hdr, err := c.doRequestOnce(ctx, method, endpoint, body)
		if err != nil {
			return nil, 0, nil, err
		}
		rl := parseRateLimitHeaders(hdr)
		if isRateLimitResponse(status, rl, raw) {
			if attempt == maxRateLimitRetries {
				return nil, status, hdr, newAPIError(endpoint, status, raw, hdr)
			}
			wait := rateLimitWait(rl, attempt)
			select {
			case <-ctx.Done():
				return nil, 0, nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		return raw, status, hdr, nil
	}
	return nil, 0, nil, fmt.Errorf("github request %s: rate limit retries exhausted", endpoint)
}

func (c *Client) doRequestOnce(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, int, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, 0, nil, err
	}
	c.setHeaders(req)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, resp.StatusCode, resp.Header, err
	}
	return raw, resp.StatusCode, resp.Header, nil
}

func (c *Client) setHeaders(req *http.Request) {
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

func (c *Client) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) pollEvery() time.Duration {
	if c.PollEvery > 0 {
		return c.PollEvery
	}
	return defaultPollEvery
}

func normalizeSBOMJSON(body []byte) ([]byte, error) {
	var wrap struct {
		SBOM json.RawMessage `json:"sbom"`
	}
	if err := json.Unmarshal(body, &wrap); err == nil && len(wrap.SBOM) > 0 {
		if json.Valid(wrap.SBOM) {
			return wrap.SBOM, nil
		}
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("github sbom: response is not valid JSON")
	}
	return body, nil
}

func readFreshCache(path string, ttl time.Duration) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	if ttl > 0 && time.Since(info.ModTime()) > ttl {
		return nil, false
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 {
		return nil, false
	}
	return body, true
}

func writeCache(path string, body []byte) error {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

func dirOf(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[:i]
	}
	return "."
}

func status(opts FetchOptions, msg string) {
	if opts.OnStatus != nil {
		opts.OnStatus(msg)
	}
}

func trimBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
