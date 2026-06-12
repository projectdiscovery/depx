package e2e

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// sourceRecord mirrors the inventory export record shape depx ingests.
type sourceRecord struct {
	Ecosystem        string   `json:"ecosystem"`
	Name             string   `json:"name"`
	PackageURL       string   `json:"package_url,omitempty"`
	PURL             string   `json:"purl,omitempty"`
	IDs              []string `json:"ids"`
	Source           string   `json:"source,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	AllVersions      bool     `json:"all_versions"`
	AffectedVersions []string `json:"affected_versions,omitempty"`
	Summary          string   `json:"summary"`
	References       []string `json:"references,omitempty"`
	ModifiedAt       string   `json:"modified_at"`
	PublishedAt      string   `json:"published_at"`
	ImportedAt       string   `json:"imported_at"`
}

// defaultSourceRecords is the fixed corpus served to e2e tests: it covers the
// malicious packages (evil-pkg, apkeep, bad-pkg) the suite asserts on.
func defaultSourceRecords() []sourceRecord {
	recent := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	older := time.Now().UTC().Add(-120 * time.Hour).Format(time.RFC3339)
	return []sourceRecord{
		{
			Ecosystem: "npm", Name: "evil-pkg",
			IDs:         []string{"MAL-2026-TEST1", "GHSCAN-MAL-1"},
			Source:      "x-osint",
			AllVersions: true,
			Summary:     "Malicious code in evil-pkg (npm)",
			References:  []string{"https://example.com/evil-pkg"},
			ModifiedAt:  recent, PublishedAt: recent, ImportedAt: recent,
		},
		{
			Ecosystem: "PyPI", Name: "apkeep",
			IDs:         []string{"MAL-2026-3431", "GHSCAN-MAL-APKEEP"},
			Source:      "ossf",
			AllVersions: true,
			Summary:     "Malicious code in apkeep (PyPI)",
			References:  []string{"https://bad-packages.kam193.eu/pypi/package/apkeep"},
			ModifiedAt:  recent, PublishedAt: recent, ImportedAt: recent,
		},
		{
			Ecosystem: "PyPI", Name: "bad-pkg",
			IDs:         []string{"MAL-2026-TEST2"},
			AllVersions: true,
			Summary:     "Malicious code in bad-pkg (PyPI)",
			ModifiedAt:  older, PublishedAt: older, ImportedAt: older,
		},
	}
}

func encodeInventory(records []sourceRecord) []byte {
	envelope := map[string]any{
		"schema_version": "1",
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"source":         "pd",
		"packages":       records,
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// mockSourceServer serves the gzipped inventory export at any path.
func mockSourceServer(t *testing.T) *httptest.Server {
	t.Helper()
	return mockSourceServerWith(t, func() []sourceRecord { return defaultSourceRecords() })
}

// mockSourceServerWith serves an inventory export whose contents are produced
// by recordsFn on each request, so a test can mutate the corpus between runs.
func mockSourceServerWith(t *testing.T, recordsFn func() []sourceRecord) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(encodeInventory(recordsFn()))
	}))
}

// sourceEnv points depx at the mock inventory export.
func sourceEnv(srv *httptest.Server) []string {
	return []string{"DEPX_SOURCE_URL=" + srv.URL + "/export"}
}

// mutableRecords is a race-safe holder for inventory records a test mutates
// while the mock server reads them from its handler goroutine.
type mutableRecords struct {
	mu      sync.Mutex
	records []sourceRecord
}

func (m *mutableRecords) get() []sourceRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.records
}

func (m *mutableRecords) set(records []sourceRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = records
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
