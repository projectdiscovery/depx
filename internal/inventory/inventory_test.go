package inventory

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func gzipExport(t *testing.T, envelope map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFetchStreamsRecords(t *testing.T) {
	body := gzipExport(t, map[string]any{
		"schema_version": "1",
		"generated_at":   "2026-06-12T00:00:00Z",
		"source":         "pd",
		"packages": []map[string]any{
			{
				"ecosystem":    "npm",
				"name":         "evil-pkg",
				"ids":          []string{"MAL-2026-1", "GHSA-x"},
				"source":       "ossf",
				"all_versions": true,
				"summary":      "Malicious code in evil-pkg",
				"references":   []string{"https://example.com/e"},
				"iocs":         map[string]any{"domains": []string{"evil.example"}},
				"modified_at":  "2026-06-11T10:00:00Z",
				"published_at": "2026-06-10T10:00:00Z",
				"imported_at":  "2026-06-11T11:00:00Z",
			},
			{
				"ecosystem":         "PyPI",
				"name":              "bad-pkg",
				"ids":               []string{"MAL-2026-2"},
				"affected_versions": []string{"1.0.0", "1.0.1"},
				"summary":           "Malicious code in bad-pkg",
			},
		},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/gzip" {
			t.Errorf("Accept header = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	var got []Record
	snap, err := Fetch(context.Background(), srv.URL, "depx-test", "", func(rec Record) error {
		got = append(got, rec)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if snap.NotModified {
		t.Fatal("unexpected NotModified on 200")
	}
	if snap.SchemaVersion != "1" || snap.Source != "pd" {
		t.Fatalf("snapshot meta = %+v", snap)
	}
	if snap.ETag != `"v1"` {
		t.Fatalf("etag = %q", snap.ETag)
	}
	if snap.GeneratedAt.IsZero() {
		t.Fatal("generated_at not parsed")
	}
	if len(got) != 2 {
		t.Fatalf("records = %d, want 2", len(got))
	}

	first := got[0]
	if first.Name != "evil-pkg" || first.Ecosystem != "npm" {
		t.Fatalf("first record = %+v", first)
	}
	if !first.AllVersions {
		t.Fatal("expected all_versions true")
	}
	if first.PrimaryID() != "MAL-2026-1" {
		t.Fatalf("primary id = %q", first.PrimaryID())
	}
	if len(first.IOCs.Domains) != 1 || first.IOCs.Domains[0] != "evil.example" {
		t.Fatalf("iocs = %+v", first.IOCs)
	}
	if first.ModifiedAt.IsZero() || first.PublishedAt.IsZero() || first.ImportedAt.IsZero() {
		t.Fatalf("timestamps not parsed: %+v", first)
	}

	second := got[1]
	if second.AllVersions {
		t.Fatal("bad-pkg should not be all_versions")
	}
	if len(second.AffectedVersions) != 2 {
		t.Fatalf("affected versions = %+v", second.AffectedVersions)
	}
}

func TestFetchNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != `"v1"` {
			t.Errorf("If-None-Match = %q", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	called := false
	snap, err := Fetch(context.Background(), srv.URL, "depx-test", `"v1"`, func(Record) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !snap.NotModified {
		t.Fatal("expected NotModified")
	}
	if snap.ETag != `"v1"` {
		t.Fatalf("etag = %q", snap.ETag)
	}
	if called {
		t.Fatal("onRecord must not be called on 304")
	}
}

func TestFetchNonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := Fetch(context.Background(), srv.URL, "depx-test", "", func(Record) error { return nil }); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestSourceURLOverride(t *testing.T) {
	t.Setenv("DEPX_SOURCE_URL", "https://mirror.example/export")
	if got := SourceURL(); got != "https://mirror.example/export" {
		t.Fatalf("SourceURL = %q", got)
	}
	if got := PackagePageURL("MAL-2026-1"); got != "https://mirror.example/packages/MAL-2026-1" {
		t.Fatalf("PackagePageURL = %q", got)
	}
}

func TestSourceURLDefault(t *testing.T) {
	t.Setenv("DEPX_SOURCE_URL", "")
	if got := SourceURL(); got != DefaultSourceURL {
		t.Fatalf("SourceURL = %q, want default", got)
	}
}
