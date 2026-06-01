package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
)

func TestPDProviderFeed(t *testing.T) {
	recent := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	old := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/github/malicious/packages" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"packages": []map[string]any{
					{
						"mal_id":     "GHSCAN-MAL-1",
						"ecosystem":  "npm",
						"pkg_name":   "evil-pkg",
						"summary":    "test malicious",
						"modified":   recent,
						"published":  recent,
						"source":     "x-osint",
						"all_versions": true,
					},
					{
						"mal_id":    "GHSCAN-MAL-2",
						"ecosystem": "pypi",
						"pkg_name":  "old-pkg",
						"summary":   "stale",
						"modified":  old,
					},
				},
			},
			"meta": map[string]any{
				"page":        1,
				"per_page":    100,
				"total":       2,
				"total_pages": 1,
			},
		})
	}))
	defer srv.Close()

	t.Setenv("DEPX_INTEL_SOURCE", "pd")
	t.Setenv("DEPX_PD_API_TOKEN", "test-token")
	t.Setenv("DEPX_PD_API_URL", srv.URL)

	cfg := &config.Config{
		Feed: config.FeedConfig{
			Since: 24 * time.Hour,
			Limit: 25,
		},
	}
	p, err := NewPD("test", cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := p.Feed(context.Background(), FeedRequest{
		Since: 24 * time.Hour,
		Limit: 25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Total != 1 {
		t.Fatalf("total in window = %d, want 1", resp.Total)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(resp.Entries))
	}
	if resp.Entries[0].Name != "evil-pkg" {
		t.Fatalf("name = %q", resp.Entries[0].Name)
	}
	if resp.Entries[0].Ecosystem != "npm" {
		t.Fatalf("ecosystem = %q", resp.Entries[0].Ecosystem)
	}
}

func TestPDProviderSearchUsesLocalIndex(t *testing.T) {
	recent := time.Now().UTC().Format(time.RFC3339)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/github/malicious/packages" && r.URL.Query().Get("mal_id") == "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"packages": []map[string]any{
						{
							"mal_id":       "GHSCAN-MAL-APKEEP",
							"ecosystem":    "pypi",
							"pkg_name":     "apkeep",
							"summary":      "malicious apkeep",
							"modified":     recent,
							"published":    recent,
							"source":       "x-osint",
							"all_versions": true,
						},
						{
							"mal_id":       "GHSCAN-MAL-UTILS",
							"ecosystem":    "npm",
							"pkg_name":     "apkeep-utils",
							"summary":      "malicious apkeep-utils",
							"modified":     recent,
							"published":    recent,
							"source":       "x-osint",
							"all_versions": true,
						},
						{
							"mal_id":    "GHSCAN-MAL-CLEAN",
							"ecosystem": "npm",
							"pkg_name":  "lodash",
							"summary":   "other",
							"modified":  recent,
						},
					},
				},
				"meta": map[string]any{
					"page": 1, "per_page": 1000, "total": 3, "total_pages": 1,
				},
			})
		case r.URL.Path == "/github/malicious/packages/GHSCAN-MAL-APKEEP":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"mal_id": "GHSCAN-MAL-APKEEP", "ecosystem": "pypi", "pkg_name": "apkeep",
					"summary": "malicious apkeep", "modified": recent, "published": recent, "source": "x-osint",
				},
			})
		case r.URL.Path == "/github/malicious/packages/GHSCAN-MAL-UTILS":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"data": map[string]any{
					"mal_id": "GHSCAN-MAL-UTILS", "ecosystem": "npm", "pkg_name": "apkeep-utils",
					"summary": "malicious apkeep-utils", "modified": recent, "published": recent, "source": "x-osint",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("DEPX_DISABLE_EMBEDDED_SEED", "1")
	t.Setenv("DEPX_INTEL_SOURCE", "pd")
	t.Setenv("DEPX_PD_API_TOKEN", "test-token")
	t.Setenv("DEPX_PD_API_URL", srv.URL)

	cfg := &config.Config{
		CacheDir: t.TempDir(),
		Feed:     config.FeedConfig{Limit: 25},
	}
	p, err := NewPD("test", cfg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := p.Search(context.Background(), SearchRequest{Query: "apk", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("entries = %d, want 2 substring matches for apk: %+v", len(resp.Entries), resp.Entries)
	}
}

func TestNewSelectsPDWhenEnabled(t *testing.T) {
	t.Setenv("DEPX_INTEL_SOURCE", "pd")
	t.Setenv("DEPX_PD_API_TOKEN", "tok")
	t.Setenv("DEPX_PD_API_URL", "https://example.test")

	p, err := New("test", &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "pd" {
		t.Fatalf("provider = %q", p.Name())
	}

	t.Setenv("DEPX_INTEL_SOURCE", "osv")
	p, err = New("test", &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "osv" {
		t.Fatalf("provider = %q", p.Name())
	}
}
