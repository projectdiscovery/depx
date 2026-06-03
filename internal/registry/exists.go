package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/projectdiscovery/depx/internal/ref"
)

// FindInEcosystems returns ecosystems where the package name exists in the registry.
func (c *Client) FindInEcosystems(ctx context.Context, name, version string, ecosystems []string) []string {
	if c == nil || name == "" || len(ecosystems) == 0 {
		return nil
	}

	found := make([]string, 0, len(ecosystems))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, eco := range ecosystems {
		wg.Add(1)
		go func(eco string) {
			defer wg.Done()
			ok, err := c.Exists(ctx, eco, name, version)
			if err != nil || !ok {
				return
			}
			mu.Lock()
			found = append(found, eco)
			mu.Unlock()
		}(eco)
	}
	wg.Wait()
	return found
}

// Exists reports whether a package name is published in the given ecosystem registry.
func (c *Client) Exists(ctx context.Context, ecosystem, name, version string) (bool, error) {
	if c == nil {
		return false, nil
	}
	key := existsCacheKey(ecosystem, name, version)
	if cached, ok := c.existsCache.Load(key); ok {
		return cached.(bool), nil
	}
	ok, err := c.probeExists(ctx, ecosystem, name, version)
	if err != nil {
		return false, err
	}
	c.existsCache.Store(key, ok)
	return ok, nil
}

func existsCacheKey(ecosystem, name, version string) string {
	return ecosystem + "\x00" + name + "\x00" + version
}

func (c *Client) probeExists(ctx context.Context, ecosystem, name, version string) (bool, error) {
	pkg := ref.PackageRef{
		Ecosystem: ecosystem,
		Name:      name,
		Version:   version,
	}

	switch ecosystem {
	case "npm", "PyPI":
		status, err := c.Status(ctx, pkg)
		if err != nil || status == nil {
			return false, err
		}
		switch status.Status {
		case "found", "yanked":
			return true, nil
		case "version_not_found":
			return true, nil
		default:
			return false, nil
		}
	case "crates.io":
		return c.cratesExists(ctx, name, version)
	case "RubyGems":
		return c.rubyGemsExists(ctx, name, version)
	case "Go":
		return c.goExists(ctx, name, version)
	default:
		return false, nil
	}
}

func (c *Client) cratesExists(ctx context.Context, name, version string) (bool, error) {
	endpoint := fmt.Sprintf("https://crates.io/api/v1/crates/%s", url.PathEscape(name))
	if version != "" {
		endpoint = fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s", url.PathEscape(name), url.PathEscape(version))
	}
	return c.registryGETExists(ctx, endpoint)
}

func (c *Client) rubyGemsExists(ctx context.Context, name, version string) (bool, error) {
	endpoint := fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", url.PathEscape(name))
	if version != "" {
		endpoint = fmt.Sprintf("https://rubygems.org/api/v1/gems/%s/versions/%s.json", url.PathEscape(name), url.PathEscape(version))
	}
	return c.registryGETExists(ctx, endpoint)
}

func (c *Client) goExists(ctx context.Context, name, version string) (bool, error) {
	escaped := strings.ReplaceAll(url.PathEscape(name), "%2F", "/")
	endpoint := fmt.Sprintf("https://proxy.golang.org/%s/@v/list", escaped)
	if version != "" {
		endpoint = fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.info", escaped, url.PathEscape(version))
	}
	ok, err := c.registryGETExists(ctx, endpoint)
	if err != nil || ok || version != "" {
		return ok, err
	}
	body, status, err := c.registryGETBody(ctx, endpoint)
	if err != nil {
		return false, err
	}
	if status == http.StatusOK {
		return strings.TrimSpace(body) != "" && body != "[]", nil
	}
	return false, nil
}

func (c *Client) registryGETExists(ctx context.Context, endpoint string) (bool, error) {
	_, status, err := c.registryGETBody(ctx, endpoint)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound, http.StatusGone:
		return false, nil
	default:
		return false, fmt.Errorf("registry lookup: status %d", status)
	}
}

func (c *Client) registryGETBody(ctx context.Context, endpoint string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, nil
	}
	// Ignore JSON parse failures; HTTP 200 is enough for existence probes.
	_ = json.Valid(body)
	return string(body), resp.StatusCode, nil
}
