package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mockGitHubBreakServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	goodSBOM := map[string]any{
		"sbom": map[string]any{
			"spdxVersion": "SPDX-2.3",
			"name":        "github/breakorg/good",
			"packages": []map[string]string{
				{"name": "npm:lodash", "versionInfo": "4.17.21"},
			},
		},
	}
	emptySBOM := map[string]any{
		"sbom": map[string]any{
			"spdxVersion": "SPDX-2.3",
			"name":        "github/breakorg/empty-sbom",
			"packages":    []map[string]string{},
		},
	}

	mux.HandleFunc("/orgs/breakorg/repos", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"full_name": "breakorg/good", "name": "good"},
			{"full_name": "breakorg/bad", "name": "bad"},
			{"full_name": "breakorg/garbage", "name": "garbage"},
			{"full_name": "breakorg/missing", "name": "missing", "archived": true},
		})
	})
	mux.HandleFunc("/users/breakorg/repos", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/orgs/emptyorg/repos", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})
	mux.HandleFunc("/users/emptyorg/repos", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{})
	})
	mux.HandleFunc("/orgs/missingorg/repos", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/users/missingorg/repos", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	mux.HandleFunc("/repos/breakorg/good/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(goodSBOM)
	})
	mux.HandleFunc("/repos/breakorg/empty-sbom/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(emptySBOM)
	})
	mux.HandleFunc("/repos/breakorg/garbage/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not-json"))
	})
	mux.HandleFunc("/repos/breakorg/async/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "timeout", http.StatusGatewayTimeout)
	})
	mux.HandleFunc("/repos/breakorg/async/dependency-graph/sbom/generate-report", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sbom_url":"invalid"}`))
	})

	mux.HandleFunc("/repos/breakorg/bad/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/repos/breakorg/bad/contents", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{})
	})
	mux.HandleFunc("/repos/breakorg/missing/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/repos/breakorg/missing/contents", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	mux.HandleFunc("/repos/breakorg/gomod/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/repos/breakorg/gomod/contents", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{"name": "go.mod", "type": "file", "download_url": "http://" + r.Host + "/download/breakorg/gomod/go.mod"},
		})
	})
	mux.HandleFunc("/download/breakorg/gomod/go.mod", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("module breakorg/gomod\n\ngo 1.22\n\nrequire example.com/lib v1.0.0\n"))
	})

	mux.HandleFunc("/repos/breakorg/bad-contents/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/repos/breakorg/bad-contents/contents", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"login": "octocat"})
	})
	mux.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"full_name": "octocat/app", "name": "app"},
		})
	})
	mux.HandleFunc("/repos/octocat/app/dependency-graph/sbom", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(goodSBOM)
	})

	return httptest.NewServer(mux)
}
