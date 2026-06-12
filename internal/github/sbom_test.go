package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchSBOMSync(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/app/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sbom": map[string]any{
				"spdxVersion": "SPDX-2.3",
				"name":        "github/acme/app",
				"packages": []map[string]string{
					{"name": "npm:lodash", "versionInfo": "4.17.21"},
				},
			},
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cacheDir := t.TempDir()
	client := NewClient("depx-test", "", time.Second)
	client.APIBase = srv.URL

	repo := Repo{Owner: "acme", Name: "app"}
	path, err := client.FetchSBOM(context.Background(), repo, FetchOptions{
		CacheDir: cacheDir,
	})
	if err != nil {
		t.Fatalf("FetchSBOM: %v", err)
	}
	if path != repo.CachePath(cacheDir) {
		t.Fatalf("unexpected cache path: %s", path)
	}

	path2, err := client.FetchSBOM(context.Background(), repo, FetchOptions{
		CacheDir: cacheDir,
	})
	if err != nil {
		t.Fatalf("cached FetchSBOM: %v", err)
	}
	if path2 != path {
		t.Fatalf("expected cached path %s, got %s", path, path2)
	}
}

func TestFetchSBOMAsync(t *testing.T) {
	var polls int
	srv := httptest.NewServer(nil)
	srvURL := srv.URL
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/app/dependency-graph/sbom":
			http.Error(w, "timeout", http.StatusGatewayTimeout)
		case "/repos/acme/app/dependency-graph/sbom/generate-report":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sbom_url": srvURL + "/repos/acme/app/dependency-graph/sbom/fetch-report/test-uuid",
			})
		case "/repos/acme/app/dependency-graph/sbom/fetch-report/test-uuid":
			polls++
			if polls < 2 {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"spdxVersion": "SPDX-2.3",
				"name":        "github/acme/app",
				"packages":    []map[string]string{},
			})
		default:
			http.NotFound(w, r)
		}
	})
	defer srv.Close()

	cacheDir := t.TempDir()
	client := NewClient("depx-test", "", time.Second)
	client.APIBase = srv.URL
	client.PollEvery = 10 * time.Millisecond

	path, err := client.FetchSBOM(context.Background(), Repo{Owner: "acme", Name: "app"}, FetchOptions{
		CacheDir: cacheDir,
	})
	if err != nil {
		t.Fatalf("FetchSBOM async: %v", err)
	}
	if path == "" {
		t.Fatal("expected cache path")
	}
	if polls < 2 {
		t.Fatalf("expected polling, got %d", polls)
	}
}
