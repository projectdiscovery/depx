package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// IsNPMSecurityHolding reports whether npm registry publishes only *-security
// placeholder version(s) for name (takedown holding package).
func (c *Client) IsNPMSecurityHolding(ctx context.Context, name string) (bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return false, nil
	}
	if v, ok := c.npmHoldingCache.Load(name); ok {
		return v.(bool), nil
	}
	holding, err := c.fetchNPMSecurityHolding(ctx, name)
	if err != nil {
		return false, err
	}
	c.npmHoldingCache.Store(name, holding)
	return holding, nil
}

func (c *Client) fetchNPMSecurityHolding(ctx context.Context, name string) (bool, error) {
	url := npmPackageDocURL(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("npm registry: status %d", resp.StatusCode)
	}

	var doc struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return false, err
	}
	if len(doc.Versions) == 0 {
		return false, nil
	}
	for version := range doc.Versions {
		if !strings.HasSuffix(strings.ToLower(strings.TrimSpace(version)), "-security") {
			return false, nil
		}
	}
	return true, nil
}

// ShouldSkipPlaceholder returns true for npm registry security stubs: either the
// dependency version is *-security or npm only publishes holding versions.
func (c *Client) ShouldSkipPlaceholder(ctx context.Context, ecosystem, name, version string) (bool, error) {
	if IsNPMSecurityVersion(ecosystem, version) {
		return true, nil
	}
	if !isNPMEcosystem(ecosystem) || c == nil {
		return false, nil
	}
	return c.IsNPMSecurityHolding(ctx, name)
}

func isNPMEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "javascript", "js":
		return true
	default:
		return false
	}
}

// IsNPMSecurityVersion reports whether version is npm's *-security stub suffix.
func IsNPMSecurityVersion(ecosystem, version string) bool {
	version = strings.TrimSpace(version)
	if version == "" || !isNPMEcosystem(ecosystem) {
		return false
	}
	return strings.HasSuffix(strings.ToLower(version), "-security")
}
