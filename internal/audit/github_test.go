package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/github"
)

func TestMaterializeGitHubAuditPath(t *testing.T) {
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
	client := github.NewClient("depx-test", "", time.Second)
	client.APIBase = srv.URL

	paths, labels, err := materializeAuditPaths(context.Background(), []string{"github:acme/app"}, &GitHubOptions{
		Client:   client,
		CacheDir: cacheDir,
	}, nil)
	if err != nil {
		t.Fatalf("materializeAuditPaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %v", paths)
	}
	if labels[paths[0]] != "github:acme/app" {
		t.Fatalf("unexpected label map: %v", labels)
	}

	targets, err := resolveAuditTargets(paths)
	if err != nil {
		t.Fatal(err)
	}
	attachSourceLabels(targets, labels)
	if targets[0].sourceLabels[paths[0]] != "github:acme/app" {
		t.Fatalf("label not attached: %+v", targets[0])
	}

	jobs := collectExtractJobs(targets)
	if len(jobs) != 1 || jobs[0].label != "github:acme/app" {
		t.Fatalf("unexpected jobs: %+v", jobs)
	}
	if filepath.Base(jobs[0].path) != "sbom.spdx.json" {
		t.Fatalf("expected cached sbom path, got %s", jobs[0].path)
	}
}

func TestEnrichFindingGitHubSource(t *testing.T) {
	f := enrichFinding(Finding{
		Source:     "github:acme/app",
		SourceType: string(SourceTypeSBOM),
		Ecosystem:  "npm",
		Name:       "lodash",
	})
	if f.ProjectURL != "https://github.com/acme/app" {
		t.Fatalf("unexpected project url: %s", f.ProjectURL)
	}
}

func TestMaterializeGitHubScanSkipsFailedRepos(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/good/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sbom": map[string]any{
				"spdxVersion": "SPDX-2.3",
				"name":        "github/acme/good",
				"packages":    []map[string]string{},
			},
		})
	})
	mux.HandleFunc("/repos/acme/bad/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/repos/acme/bad/contents", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cacheDir := t.TempDir()
	client := github.NewClient("depx-test", "", time.Second)
	client.APIBase = srv.URL

	paths, labels, err := materializeAuditPaths(context.Background(), []string{
		"github:acme/good",
		"github:acme/bad",
	}, &GitHubOptions{
		Client:   client,
		CacheDir: cacheDir,
	}, nil)
	if err != nil {
		t.Fatalf("materializeAuditPaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %v", paths)
	}
	if labels[paths[0]] != "github:acme/good" {
		t.Fatalf("unexpected label map: %v", labels)
	}
}

func TestMaterializeGitHubScanParallel(t *testing.T) {
	var peak int32
	var active int32
	repos := []string{"acme/a", "acme/b", "acme/c", "acme/d", "acme/e"}
	mux := http.NewServeMux()
	for _, slug := range repos {
		slug := slug
		mux.HandleFunc("/repos/"+slug+"/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
			cur := atomic.AddInt32(&active, 1)
			for {
				old := atomic.LoadInt32(&peak)
				if cur <= old || atomic.CompareAndSwapInt32(&peak, old, cur) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			atomic.AddInt32(&active, -1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sbom": map[string]any{
					"spdxVersion": "SPDX-2.3",
					"name":        "github/" + slug,
					"packages":    []map[string]string{},
				},
			})
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cacheDir := t.TempDir()
	client := github.NewClient("depx-test", "", time.Second)
	client.APIBase = srv.URL

	inputs := make([]string, len(repos))
	for i, slug := range repos {
		inputs[i] = "github:" + slug
	}
	paths, labels, err := materializeAuditPaths(context.Background(), inputs, &GitHubOptions{
		Client:   client,
		CacheDir: cacheDir,
	}, nil)
	if err != nil {
		t.Fatalf("materializeAuditPaths: %v", err)
	}
	if len(paths) != len(repos) {
		t.Fatalf("expected %d paths, got %d", len(repos), len(paths))
	}
	if atomic.LoadInt32(&peak) < 2 {
		t.Fatalf("expected parallel fetches, peak concurrency %d", peak)
	}
	for _, slug := range repos {
		ref := "github:" + slug
		found := false
		for _, p := range paths {
			if labels[p] == ref {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing label for %s: %v", ref, labels)
		}
	}
}

func TestMaterializeGitHubScanAllSkippedFails(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/bad/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/repos/acme/bad/contents", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cacheDir := t.TempDir()
	client := github.NewClient("depx-test", "", time.Second)
	client.APIBase = srv.URL

	_, _, err := materializeAuditPaths(context.Background(), []string{"github:acme/bad"}, &GitHubOptions{
		Client:   client,
		CacheDir: cacheDir,
	}, nil)
	if err == nil {
		t.Fatal("expected error when all repos skipped")
	}
}
