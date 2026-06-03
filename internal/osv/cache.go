package osv

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type cachedVuln struct {
	FetchedAt time.Time     `json:"fetched_at"`
	Record    Vulnerability `json:"record"`
}

func (c *Client) getCachedVuln(id string) (*Vulnerability, bool) {
	if c.cacheDir == "" || c.bypassCache {
		return nil, false
	}
	path := vulnCachePath(c.cacheDir, id)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cached cachedVuln
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, false
	}
	if c.cacheTTL > 0 && time.Since(cached.FetchedAt) > c.cacheTTL {
		return nil, false
	}
	v := cached.Record
	return &v, true
}

// getCachedVulnStale returns a cached vulnerability even when the TTL has
// expired. Used for non-blocking feed rendering.
func (c *Client) getCachedVulnStale(id string) (*Vulnerability, bool) {
	if c.cacheDir == "" || c.bypassCache {
		return nil, false
	}
	path := vulnCachePath(c.cacheDir, id)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cached cachedVuln
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, false
	}
	v := cached.Record
	return &v, true
}

func (c *Client) writeCachedVuln(id string, vuln *Vulnerability) {
	if c.cacheDir == "" || c.bypassCache || vuln == nil {
		return
	}
	path := vulnCachePath(c.cacheDir, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	payload, err := json.Marshal(cachedVuln{
		FetchedAt: time.Now().UTC(),
		Record:    *vuln,
	})
	if err != nil {
		return
	}
	_ = os.WriteFile(path, payload, 0o644)
}

func vulnCachePath(cacheDir, id string) string {
	return filepath.Join(cacheDir, "vulns", id+".json")
}

type cachedQuery struct {
	FetchedAt time.Time     `json:"fetched_at"`
	Response  QueryResponse `json:"response"`
}

func (c *Client) getCachedQuery(q QueryRequest) (*QueryResponse, bool) {
	if c.cacheDir == "" || c.bypassCache {
		return nil, false
	}
	path := queryCachePath(c.cacheDir, q)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var cached cachedQuery
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, false
	}
	if c.cacheTTL > 0 && time.Since(cached.FetchedAt) > c.cacheTTL {
		return nil, false
	}
	resp := cached.Response
	return &resp, true
}

func (c *Client) writeCachedQuery(q QueryRequest, resp *QueryResponse) {
	if c.cacheDir == "" || c.bypassCache || resp == nil {
		return
	}
	path := queryCachePath(c.cacheDir, q)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	payload, err := json.Marshal(cachedQuery{
		FetchedAt: time.Now().UTC(),
		Response:  *resp,
	})
	if err != nil {
		return
	}
	_ = os.WriteFile(path, payload, 0o644)
}

func queryCachePath(cacheDir string, q QueryRequest) string {
	key, _ := json.Marshal(q)
	sum := sha256.Sum256(key)
	return filepath.Join(cacheDir, "queries", fmt.Sprintf("%x.json", sum))
}

func parseOSVTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), nil
	}
	return time.Parse(time.RFC3339, raw)
}
