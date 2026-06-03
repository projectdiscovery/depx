package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/depx/internal/ref"
)

type Client struct {
	httpClient      *http.Client
	userAgent       string
	existsCache     sync.Map // key: ecosystem\x00name\x00version -> bool
	npmHoldingCache sync.Map // key: npm package name -> bool
}

type Status struct {
	Status   string `json:"status"`
	Yanked   bool   `json:"yanked"`
	YankedAt string `json:"yanked_at,omitempty"`
}

func NewClient(userAgent string, timeout time.Duration) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		userAgent:  userAgent,
	}
}

func (c *Client) Status(ctx context.Context, pkg ref.PackageRef) (*Status, error) {
	switch pkg.Ecosystem {
	case "npm":
		return c.npmStatus(ctx, pkg)
	case "PyPI":
		return c.pypiStatus(ctx, pkg)
	default:
		return nil, nil
	}
}

var npmRegistryBase = "https://registry.npmjs.org"

func npmPackageDocURL(name string) string {
	return npmRegistryBase + "/" + strings.TrimPrefix(name, "/")
}

func (c *Client) npmStatus(ctx context.Context, pkg ref.PackageRef) (*Status, error) {
	url := npmPackageDocURL(pkg.Name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
		return &Status{Status: "not_found"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm registry: status %d", resp.StatusCode)
	}

	var doc struct {
		Name     string                     `json:"name"`
		Versions map[string]json.RawMessage `json:"versions"`
		Time     map[string]string          `json:"time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	version := pkg.Version
	if version == "" {
		return &Status{Status: "found"}, nil
	}
	if _, ok := doc.Versions[version]; !ok {
		return &Status{Status: "version_not_found"}, nil
	}
	return &Status{Status: "found"}, nil
}

func (c *Client) pypiStatus(ctx context.Context, pkg ref.PackageRef) (*Status, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", pkg.Name)
	if pkg.Version != "" {
		url = fmt.Sprintf("https://pypi.org/pypi/%s/%s/json", pkg.Name, pkg.Version)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &Status{Status: "not_found"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("pypi registry: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var doc struct {
		Info struct {
			Yanked bool   `json:"yanked"`
			Reason string `json:"yanked_reason"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	status := &Status{Status: "found", Yanked: doc.Info.Yanked}
	if doc.Info.Yanked {
		status.Status = "yanked"
	}
	return status, nil
}
