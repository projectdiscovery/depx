package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mockPDServer(t *testing.T) *httptest.Server {
	t.Helper()
	recent := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	older := time.Now().UTC().Add(-120 * time.Hour).Format(time.RFC3339)

	packages := []map[string]any{
		{
			"mal_id": "GHSCAN-MAL-1", "ecosystem": "npm", "pkg_name": "evil-pkg",
			"summary": "Malicious code in evil-pkg (npm)", "modified": recent, "published": recent,
			"all_versions": true, "source": "x-osint",
		},
		{
			"mal_id": "GHSCAN-MAL-APKEEP", "ecosystem": "pypi", "pkg_name": "apkeep",
			"summary": "Malicious code in apkeep (PyPI)", "modified": recent, "published": recent,
			"all_versions": true, "source": "x-osint",
			"references": []string{"https://bad-packages.kam193.eu/pypi/package/apkeep"},
		},
		{
			"mal_id": "GHSCAN-MAL-2", "ecosystem": "pypi", "pkg_name": "bad-pkg",
			"summary": "Malicious code in bad-pkg (PyPI)", "modified": older, "published": older,
			"all_versions": true,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/github/malicious/packages", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/github/malicious/packages" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"packages": packages},
			"meta":    map[string]any{"page": 1, "per_page": 1000, "total": len(packages), "total_pages": 1},
		})
	})
	mux.HandleFunc("/github/malicious/packages/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/github/malicious/packages/")
		for _, pkg := range packages {
			if pkg["mal_id"] == id {
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": pkg})
				return
			}
		}
		http.NotFound(w, r)
	})

	registerOSVAPIRoutes(mux)
	return httptest.NewServer(mux)
}
