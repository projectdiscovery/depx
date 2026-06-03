package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/osv"
)

func TestOSVFeedUsesStaleIndexWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "feed", "index.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	entries := []osv.IndexEntry{{
		ID:        "MAL-CACHED-1",
		Ecosystem: "npm",
		Modified:  time.Now().UTC(),
	}}
	payload, err := json.Marshal(struct {
		FetchedAt time.Time        `json:"fetched_at"`
		Entries   []osv.IndexEntry `json:"entries"`
	}{
		FetchedAt: time.Now().UTC().Add(-48 * time.Hour),
		Entries:   entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	vulnPath := filepath.Join(dir, "vulns", "MAL-CACHED-1.json")
	if err := os.MkdirAll(filepath.Dir(vulnPath), 0o755); err != nil {
		t.Fatal(err)
	}
	vulnPayload, err := json.Marshal(struct {
		FetchedAt time.Time          `json:"fetched_at"`
		Record    *osv.Vulnerability `json:"record"`
	}{
		FetchedAt: time.Now().UTC(),
		Record: &osv.Vulnerability{
			ID:        "MAL-CACHED-1",
			Summary:   "Malicious code in cached-pkg (npm)",
			Published: time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339),
			Affected: []osv.Affected{{
				Package: &osv.Package{Name: "cached-pkg", Ecosystem: "npm"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vulnPath, vulnPayload, 0o644); err != nil {
		t.Fatal(err)
	}

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "should not be called", http.StatusTeapot)
	}))
	defer srv.Close()

	t.Setenv("DEPX_MODIFIED_INDEX_URL", srv.URL+"/modified_id.csv")

	p := NewOSV("test", &config.Config{
		CacheDir: dir,
		Timeout:  time.Second,
		Feed:     config.FeedConfig{Since: 72 * time.Hour, Limit: 25, CacheTTL: time.Hour},
	})
	resp, err := p.Feed(context.Background(), FeedRequest{Since: 72 * time.Hour, Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("expected no network fetch for stale feed index, got %d hits", hits)
	}
	if len(resp.Entries) != 1 || resp.Entries[0].IDs[0] != "MAL-CACHED-1" {
		t.Fatalf("unexpected feed entries: %+v", resp.Entries)
	}
	if resp.Entries[0].Name != "cached-pkg" {
		t.Fatalf("expected package name from cached vuln blob, got %q", resp.Entries[0].Name)
	}
	if !resp.FromCache {
		t.Fatal("expected FromCache=true for stale index")
	}
}

func TestOSVFeedEnrichesPackageNameFromCache(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "feed", "index.json")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	entries := []osv.IndexEntry{{
		ID:        "MAL-2026-5167",
		Ecosystem: "PyPI",
		Modified:  time.Now().UTC(),
	}}
	payload, err := json.Marshal(struct {
		FetchedAt time.Time        `json:"fetched_at"`
		Entries   []osv.IndexEntry `json:"entries"`
	}{
		FetchedAt: time.Now().UTC(),
		Entries:   entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	vulnPath := filepath.Join(dir, "vulns", "MAL-2026-5167.json")
	if err := os.MkdirAll(filepath.Dir(vulnPath), 0o755); err != nil {
		t.Fatal(err)
	}
	vulnPayload, err := json.Marshal(struct {
		FetchedAt time.Time          `json:"fetched_at"`
		Record    *osv.Vulnerability `json:"record"`
	}{
		FetchedAt: time.Now().UTC(),
		Record: &osv.Vulnerability{
			ID:        "MAL-2026-5167",
			Summary:   "Malicious code in spaysdata (PyPI)",
			Published: time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339),
			Affected: []osv.Affected{{
				Package: &osv.Package{Name: "spaysdata", Ecosystem: "PyPI"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vulnPath, vulnPayload, 0o644); err != nil {
		t.Fatal(err)
	}

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "should not be called", http.StatusTeapot)
	}))
	defer srv.Close()

	t.Setenv("DEPX_OSV_URL", srv.URL+"/v1")
	t.Setenv("DEPX_MODIFIED_INDEX_URL", srv.URL+"/modified_id.csv")

	p := NewOSV("test", &config.Config{
		CacheDir: dir,
		Timeout:  5 * time.Second,
		Feed:     config.FeedConfig{Since: 72 * time.Hour, Limit: 25, CacheTTL: time.Hour},
	})
	resp, err := p.Feed(context.Background(), FeedRequest{Since: 72 * time.Hour, Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("expected no network fetch for cached vuln, got %d hits", hits)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("unexpected entries: %+v", resp.Entries)
	}
	if resp.Entries[0].Name != "spaysdata" {
		t.Fatalf("expected package name spaysdata, got %q", resp.Entries[0].Name)
	}
}

func TestOSVFeedExcludesOldPublishedDespiteRecentModified(t *testing.T) {
	dir := t.TempDir()
	compiledPath := filepath.Join(dir, "mal", "compiled.json")
	if err := os.MkdirAll(filepath.Dir(compiledPath), 0o755); err != nil {
		t.Fatal(err)
	}
	oldPub := time.Now().UTC().Add(-20 * 24 * time.Hour)
	recentMod := time.Now().UTC()
	payload := []byte(`{"built_at":"` + time.Now().UTC().Format(time.RFC3339) + `","entry_count":1,"packages":{"npm|stale-pkg":[{"id":"MAL-OLD-MOD","summary":"Malicious code in stale-pkg (npm)","published":"` + oldPub.Format(time.RFC3339) + `","modified":"` + recentMod.Format(time.RFC3339) + `","any_version":true}]}}`)
	if err := os.WriteFile(compiledPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "should not be called", http.StatusTeapot)
	}))
	defer srv.Close()

	t.Setenv("DEPX_OSV_URL", srv.URL+"/v1")
	t.Setenv("DEPX_MODIFIED_INDEX_URL", srv.URL+"/modified_id.csv")

	p := NewOSV("test", &config.Config{
		CacheDir: dir,
		Timeout:  5 * time.Second,
		Feed:     config.FeedConfig{Since: 72 * time.Hour, Limit: 25, CacheTTL: time.Hour},
	})
	resp, err := p.Feed(context.Background(), FeedRequest{Since: 72 * time.Hour, Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("expected no network fetch, got %d hits", hits)
	}
	if len(resp.Entries) != 0 {
		t.Fatalf("expected no entries with published outside window, got %+v", resp.Entries)
	}
}

func TestOSVFeedPreservesCompiledPublishedWhenVulnCacheIncomplete(t *testing.T) {
	dir := t.TempDir()
	compiledPath := filepath.Join(dir, "mal", "compiled.json")
	if err := os.MkdirAll(filepath.Dir(compiledPath), 0o755); err != nil {
		t.Fatal(err)
	}
	pub := time.Now().UTC().Add(-24 * time.Hour)
	mod := time.Now().UTC()
	payload := []byte(`{"built_at":"` + time.Now().UTC().Format(time.RFC3339) + `","entry_count":1,"packages":{"npm|evil-pkg":[{"id":"MAL-CACHED-1","summary":"Malicious code in evil-pkg (npm)","published":"` + pub.Format(time.RFC3339) + `","modified":"` + mod.Format(time.RFC3339) + `","any_version":true}]}}`)
	if err := os.WriteFile(compiledPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	vulnPath := filepath.Join(dir, "vulns", "MAL-CACHED-1.json")
	if err := os.MkdirAll(filepath.Dir(vulnPath), 0o755); err != nil {
		t.Fatal(err)
	}
	// Cached vuln blob without published — must not clobber compiled index published date.
	vulnPayload, err := json.Marshal(struct {
		FetchedAt time.Time          `json:"fetched_at"`
		Record    *osv.Vulnerability `json:"record"`
	}{
		FetchedAt: time.Now().UTC(),
		Record: &osv.Vulnerability{
			ID:      "MAL-CACHED-1",
			Summary: "Malicious code in evil-pkg (npm)",
			Affected: []osv.Affected{{
				Package: &osv.Package{Name: "evil-pkg", Ecosystem: "npm"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vulnPath, vulnPayload, 0o644); err != nil {
		t.Fatal(err)
	}

	p := NewOSV("test", &config.Config{
		CacheDir: dir,
		Timeout:  time.Second,
		Feed:     config.FeedConfig{Since: 72 * time.Hour, Limit: 25, CacheTTL: time.Hour},
	})
	resp, err := p.Feed(context.Background(), FeedRequest{Since: 72 * time.Hour, Limit: 25})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("unexpected entries: %+v", resp.Entries)
	}
	if resp.Entries[0].Published.IsZero() {
		t.Fatalf("expected published from compiled index, got zero: %+v", resp.Entries[0])
	}
}
