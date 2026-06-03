package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVulnDiskCache(t *testing.T) {
	dir := t.TempDir()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"MAL-TEST-1","summary":"test","published":"2026-05-25T08:00:00Z","modified":"2026-05-25T09:00:00Z"}`))
	}))
	t.Cleanup(srv.Close)

	client := NewClient("test", time.Second, WithBaseURL(srv.URL), WithCache(dir, time.Hour))
	ctx := context.Background()

	v1, err := client.GetVuln(ctx, "MAL-TEST-1")
	if err != nil {
		t.Fatal(err)
	}
	if v1.Summary != "test" || hits != 1 {
		t.Fatalf("expected one fetch, got hits=%d vuln=%+v", hits, v1)
	}

	v2, err := client.GetVuln(ctx, "MAL-TEST-1")
	if err != nil {
		t.Fatal(err)
	}
	if v2.Summary != "test" || hits != 1 {
		t.Fatalf("expected cache hit, hits=%d", hits)
	}

	if _, err := os.ReadFile(filepath.Join(dir, "vulns", "MAL-TEST-1.json")); err != nil {
		t.Fatalf("expected cache file: %v", err)
	}

	client.SetBypassCache(true)
	if _, err := client.GetVuln(ctx, "MAL-TEST-1"); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("expected bypass fetch, hits=%d", hits)
	}
}

func TestQueryDiskCache(t *testing.T) {
	dir := t.TempDir()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			hits++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"MAL-TEST-1","modified":"2026-05-25T09:00:00Z"}]}]}`))
	}))
	t.Cleanup(srv.Close)

	client := NewClient("test", time.Second, WithBaseURL(srv.URL+"/v1"), WithCache(dir, time.Hour))
	ctx := context.Background()
	q := QueryRequest{Package: &PackageQuery{Name: "evil", Ecosystem: "npm"}}

	_, err := client.QueryBatch(ctx, []QueryRequest{q})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("expected one batch fetch, got %d", hits)
	}

	_, err = client.QueryBatch(ctx, []QueryRequest{q})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("expected cache hit, got %d batch fetches", hits)
	}

	entries, _ := os.ReadDir(filepath.Join(dir, "queries"))
	if len(entries) != 1 {
		t.Fatalf("expected one query cache file, got %d", len(entries))
	}
}

func TestImportedTime(t *testing.T) {
	v := &Vulnerability{
		DatabaseSpecific: DatabaseSpecific{
			MaliciousPackagesOrigins: []MaliciousOrigin{
				{ImportTime: "2026-05-25T09:37:28.988944113Z"},
			},
		},
	}
	got := v.ImportedTime()
	if got.IsZero() || got.Format(time.RFC3339) != "2026-05-25T09:37:28Z" {
		t.Fatalf("unexpected import time: %v", got)
	}
}

func TestGetVulnCachedOnlyStale(t *testing.T) {
	dir := t.TempDir()
	path := vulnCachePath(dir, "MAL-STALE-1")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	stale := cachedVuln{
		FetchedAt: time.Now().UTC().Add(-48 * time.Hour),
		Record:    Vulnerability{ID: "MAL-STALE-1", Summary: "stale ok"},
	}
	payload, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	client := NewClient("test", time.Second, WithCache(dir, time.Hour))
	if vuln, ok := client.GetVulnCachedOnly("MAL-STALE-1"); !ok || vuln.Summary != "stale ok" {
		t.Fatalf("expected stale cache hit, got ok=%v vuln=%+v", ok, vuln)
	}
	if _, ok := client.getCachedVuln("MAL-STALE-1"); ok {
		t.Fatal("fresh cache lookup should miss expired entry")
	}
}
