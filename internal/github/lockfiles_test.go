package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResolveSourcesLockfileFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/app/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/repos/acme/app", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
	})
	mux.HandleFunc("/repos/acme/app/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": map[string]string{"sha": "tree-sha"},
		})
	})
	mux.HandleFunc("/repos/acme/app/git/trees/tree-sha", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree": []map[string]string{
				{"path": "go.mod", "type": "blob"},
			},
		})
	})
	mux.HandleFunc("/repos/acme/app/contents/go.mod", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(contentEntry{
			Name:        "go.mod",
			Path:        "go.mod",
			Type:        "file",
			DownloadURL: "http://" + r.Host + "/download/go.mod",
		})
	})
	mux.HandleFunc("/download/go.mod", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("module acme/app\n\ngo 1.22\n\nrequire example.com/lib v1.0.0\n"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cacheDir := t.TempDir()
	client := NewClient("depx-test", "", time.Second)
	client.APIBase = srv.URL

	paths, err := client.ResolveSources(context.Background(), Repo{Owner: "acme", Name: "app"}, FetchOptions{
		CacheDir: cacheDir,
	})
	if err != nil {
		t.Fatalf("ResolveSources: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 lockfile path, got %v", paths)
	}
}

func TestResolveSourcesSubdirectoryLockfile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/mono/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/repos/acme/mono", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"default_branch": "main"})
	})
	mux.HandleFunc("/repos/acme/mono/git/ref/heads/main", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"object": map[string]string{"sha": "tree-sha"},
		})
	})
	mux.HandleFunc("/repos/acme/mono/git/trees/tree-sha", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree": []map[string]string{
				{"path": "README.md", "type": "blob"},
				{"path": "frontend/package-lock.json", "type": "blob"},
				{"path": "frontend/node_modules/lodash/package-lock.json", "type": "blob"},
			},
		})
	})
	mux.HandleFunc("/repos/acme/mono/contents/frontend/package-lock.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(contentEntry{
			Name:        "package-lock.json",
			Path:        "frontend/package-lock.json",
			Type:        "file",
			DownloadURL: "http://" + r.Host + "/download/frontend/package-lock.json",
		})
	})
	mux.HandleFunc("/download/frontend/package-lock.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"lockfileVersion":2,"packages":{"":{"name":"frontend"}}}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	cacheDir := t.TempDir()
	client := NewClient("depx-test", "", time.Second)
	client.APIBase = srv.URL

	paths, err := client.ResolveSources(context.Background(), Repo{Owner: "acme", Name: "mono"}, FetchOptions{
		CacheDir: cacheDir,
	})
	if err != nil {
		t.Fatalf("ResolveSources: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 lockfile path, got %v", paths)
	}
	if !strings.Contains(paths[0], "frontend") {
		t.Fatalf("expected cached subdir lockfile, got %s", paths[0])
	}
}

func TestShouldSkipLockfilePath(t *testing.T) {
	if !shouldSkipLockfilePath("frontend/node_modules/pkg/package-lock.json") {
		t.Fatal("expected node_modules path to be skipped")
	}
	if shouldSkipLockfilePath("frontend/package-lock.json") {
		t.Fatal("expected frontend lockfile to be kept")
	}
}
