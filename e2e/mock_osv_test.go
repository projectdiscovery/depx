package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func mockModifiedIndexCSV() string {
	recent := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	older := time.Now().UTC().Add(-120 * time.Hour).Format(time.RFC3339)
	return fmt.Sprintf("%s,npm/MAL-2026-TEST1\n%s,PyPI/MAL-2026-TEST2\n", recent, older)
}

func mockOSVServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/modified_id.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(mockModifiedIndexCSV()))
	})
	registerOSVAPIRoutes(mux)
	return httptest.NewServer(mux)
}

func registerOSVAPIRoutes(mux *http.ServeMux) {
	recentPub := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	recentMod := time.Now().UTC().Format(time.RFC3339)
	mux.HandleFunc("/v1/vulns/MAL-2026-TEST1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"MAL-2026-TEST1","summary":"Malicious code in evil-pkg (npm)","published":"` + recentPub + `","modified":"` + recentMod + `","references":[{"type":"WEB","url":"https://example.com/evil-pkg"}],"affected":[{"package":{"name":"evil-pkg","ecosystem":"npm"}}]}`))
	})
	mux.HandleFunc("/v1/vulns/GHSCAN-MAL-1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"GHSCAN-MAL-1","summary":"Malicious code in evil-pkg (npm)","published":"` + recentPub + `","modified":"` + recentMod + `","references":[{"type":"WEB","url":"https://example.com/evil-pkg"}],"affected":[{"package":{"name":"evil-pkg","ecosystem":"npm"}}]}`))
	})
	mux.HandleFunc("/v1/vulns/MAL-2026-3431", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"MAL-2026-3431","summary":"Malicious code in apkeep (PyPI)","published":"2026-05-11T19:23:16Z","modified":"2026-05-11T20:46:16.684861Z","references":[{"type":"WEB","url":"https://bad-packages.kam193.eu/pypi/package/apkeep"}],"affected":[{"package":{"name":"apkeep","ecosystem":"PyPI"}}]}`))
	})
	mux.HandleFunc("/v1/vulns/GHSCAN-MAL-APKEEP", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"GHSCAN-MAL-APKEEP","summary":"Malicious code in apkeep (PyPI)","published":"2026-05-11T19:23:16Z","modified":"2026-05-11T20:46:16.684861Z","references":[{"type":"WEB","url":"https://bad-packages.kam193.eu/pypi/package/apkeep"}],"affected":[{"package":{"name":"apkeep","ecosystem":"PyPI"}}]}`))
	})
	mux.HandleFunc("/v1/vulns/MAL-2026-TEST2", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"MAL-2026-TEST2","summary":"Malicious code in bad-pkg (PyPI)","published":"` + recentPub + `","modified":"` + recentMod + `","affected":[{"package":{"name":"bad-pkg","ecosystem":"PyPI"}}]}`))
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/v1/query", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Package.Name == "evil-pkg" {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"MAL-2026-TEST1","summary":"Malicious code in evil-pkg (npm)"},{"id":"GHSCAN-MAL-1","summary":"Malicious code in evil-pkg (npm)"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	})
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		results := make([]map[string]interface{}, len(req.Queries))
		for i, q := range req.Queries {
			results[i] = batchQueryResult(q.Package.Name, q.Package.Ecosystem)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
	})
}

func batchQueryResult(name, ecosystem string) map[string]interface{} {
	if name == "apkeep" && ecosystem == "PyPI" {
		return map[string]interface{}{
			"vulns": []map[string]interface{}{
				{"id": "MAL-2026-3431", "summary": "Malicious code in apkeep (PyPI)"},
			},
		}
	}
	return map[string]interface{}{"vulns": []interface{}{}}
}

func assertJSONCommand(t *testing.T, out, command string) {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		Command       string `json:"command"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out)
	}
	if env.SchemaVersion != "1" {
		t.Fatalf("schema_version = %q", env.SchemaVersion)
	}
	if env.Command != command {
		t.Fatalf("command = %q, want %q", env.Command, command)
	}
}
