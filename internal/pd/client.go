package pd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

type Client struct {
	baseURL    string
	osvBase    string
	token      string
	httpClient *retryablehttp.Client
	userAgent  string
}

func NewClient(userAgent string, timeout time.Duration) (*Client, error) {
	token := Token()
	if token == "" {
		return nil, fmt.Errorf("DEPX_PD_API_TOKEN is required when PD intel source is enabled")
	}
	httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	httpClient.HTTPClient.Timeout = timeout
	return &Client{
		baseURL:    APIURL(),
		osvBase:    OSVBaseURL(),
		token:      token,
		httpClient: httpClient,
		userAgent:  userAgent,
	}, nil
}

func (c *Client) ListPackagesEnvelope(ctx context.Context, params ListPackagesParams) (*ListPackagesResult, error) {
	if params.PerPage <= 0 {
		params.PerPage = 100
	}
	if params.Page <= 0 {
		params.Page = 1
	}
	if params.Withdrawn == "" {
		params.Withdrawn = "exclude"
	}

	q := url.Values{}
	q.Set("page", fmt.Sprintf("%d", params.Page))
	q.Set("per_page", fmt.Sprintf("%d", params.PerPage))
	q.Set("withdrawn", params.Withdrawn)
	if params.Ecosystem != "" {
		q.Set("ecosystem", normalizeFilterEco(params.Ecosystem))
	}
	if params.Source != "" {
		q.Set("source", params.Source)
	}
	if params.Query != "" {
		q.Set("q", params.Query)
	}

	endpoint := c.baseURL + "/github/malicious/packages?" + q.Encode()
	env, err := c.getEnvelope(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	var wrap struct {
		Packages []rawPackage `json:"packages"`
	}
	if err := json.Unmarshal(env.Data, &wrap); err != nil {
		return nil, err
	}

	out := make([]Package, 0, len(wrap.Packages))
	for _, raw := range wrap.Packages {
		out = append(out, raw.decode())
	}
	meta := Meta{}
	if env.Meta != nil {
		meta = *env.Meta
	}
	return &ListPackagesResult{Packages: out, Meta: meta}, nil
}

func (c *Client) GetPackage(ctx context.Context, id string) (*Package, error) {
	endpoint := c.baseURL + "/github/malicious/packages/" + url.PathEscape(id)
	env, err := c.getEnvelope(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	var raw rawPackage
	if err := json.Unmarshal(env.Data, &raw); err != nil {
		return nil, err
	}
	pkg := raw.decode()
	return &pkg, nil
}

func (c *Client) GetVuln(ctx context.Context, id string) ([]byte, error) {
	endpoint := c.osvBase + "/vulns/" + url.PathEscape(id)
	return c.get(ctx, endpoint, false)
}

func (c *Client) Query(ctx context.Context, body []byte) ([]byte, error) {
	return c.post(ctx, c.osvBase+"/query", body)
}

func (c *Client) QueryBatch(ctx context.Context, body []byte) ([]byte, error) {
	return c.post(ctx, c.osvBase+"/querybatch", body)
}

func (c *Client) getEnvelope(ctx context.Context, endpoint string) (*envelope, error) {
	raw, err := c.do(ctx, http.MethodGet, endpoint, nil, true)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, apiError(env)
	}
	return &env, nil
}

func (c *Client) get(ctx context.Context, endpoint string, wrapped bool) (json.RawMessage, error) {
	raw, err := c.do(ctx, http.MethodGet, endpoint, nil, wrapped)
	if err != nil {
		return nil, err
	}
	if wrapped {
		var env envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, err
		}
		if !env.Success {
			return nil, apiError(env)
		}
		return env.Data, nil
	}
	return raw, nil
}

func (c *Client) post(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	return c.do(ctx, http.MethodPost, endpoint, body, false)
}

func (c *Client) do(ctx context.Context, method, endpoint string, body []byte, wrapped bool) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	}
	req, err := retryablehttp.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("pd request %s: not found", endpoint)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("pd request %s: auth failed (status %d)", endpoint, resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("pd request %s: status %d: %s", endpoint, resp.StatusCode, trimBody(raw))
	}

	if wrapped {
		return raw, nil
	}
	// OSV-compat endpoints return bare JSON; detect ghscan error envelope.
	if len(raw) > 0 && raw[0] == '{' {
		var probe struct {
			Success *bool         `json:"success"`
			Error   *APIErrorBody `json:"error"`
		}
		if json.Unmarshal(raw, &probe) == nil && probe.Success != nil && !*probe.Success {
			msg := "request failed"
			if probe.Error != nil && probe.Error.Message != "" {
				msg = probe.Error.Message
			}
			return nil, fmt.Errorf("pd request %s: %s", endpoint, msg)
		}
	}
	return raw, nil
}

type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Meta    *Meta           `json:"meta"`
	Error   *APIErrorBody   `json:"error"`
}

func apiError(env envelope) error {
	if env.Error != nil && env.Error.Message != "" {
		return fmt.Errorf("pd api: %s", env.Error.Message)
	}
	return fmt.Errorf("pd api: request failed")
}

type rawPackage struct {
	MalID            string   `json:"mal_id"`
	Ecosystem        string   `json:"ecosystem"`
	PkgName          string   `json:"pkg_name"`
	PURL             string   `json:"purl"`
	Source           string   `json:"source"`
	Severity         string   `json:"severity"`
	AllVersions      bool     `json:"all_versions"`
	AffectedVersions []string `json:"affected_versions"`
	Published        string   `json:"published"`
	Modified         string   `json:"modified"`
	Withdrawn        string   `json:"withdrawn"`
	Aliases          []string `json:"aliases"`
	References       []string `json:"references"`
	Summary          string   `json:"summary"`
	IsOSV            bool     `json:"is_osv"`
	OSVURL           string   `json:"osv_url"`
}

func (r rawPackage) decode() Package {
	return Package{
		MalID:            r.MalID,
		Ecosystem:        NormalizeEcosystem(r.Ecosystem),
		PkgName:          r.PkgName,
		PURL:             r.PURL,
		Source:           r.Source,
		Severity:         r.Severity,
		AllVersions:      r.AllVersions,
		AffectedVersions: append([]string(nil), r.AffectedVersions...),
		Published:        parseTime(r.Published),
		Modified:         parseTime(r.Modified),
		Withdrawn:        r.Withdrawn,
		Aliases:          append([]string(nil), r.Aliases...),
		References:       append([]string(nil), r.References...),
		Summary:          r.Summary,
		IsOSV:            r.IsOSV,
		OSVURL:           r.OSVURL,
	}
}

func parseTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func trimBody(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

func normalizeFilterEco(eco string) string {
	switch strings.ToLower(eco) {
	case "pypi", "python":
		return "pypi"
	case "npm", "javascript", "js":
		return "npm"
	default:
		return strings.ToLower(eco)
	}
}

// NormalizeEcosystem maps PD list ecosystem labels to OSV-style names used elsewhere in depx.
func NormalizeEcosystem(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "pypi", "python":
		return "PyPI"
	case "go", "golang":
		return "Go"
	case "crates", "cargo", "rust", "crates.io":
		return "crates.io"
	case "ruby", "gem", "rubygems":
		return "RubyGems"
	case "npm", "javascript", "js":
		return "npm"
	default:
		return eco
	}
}
