package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestQuarantineCache(t *testing.T) {
	dir := t.TempDir()

	if IsQuarantinedCached(dir, "npm", "nodemon-webpatch") {
		t.Fatal("expected miss before set")
	}
	if err := SetQuarantined(dir, "npm", "nodemon-webpatch", true); err != nil {
		t.Fatal(err)
	}
	if !IsQuarantinedCached(dir, "npm", "nodemon-webpatch") {
		t.Fatal("expected hit after set")
	}
	if !HasQuarantineCacheEntry(dir, "npm", "nodemon-webpatch") {
		t.Fatal("expected cache entry")
	}
	if IsQuarantinedCached(dir, "PyPI", "evil") {
		t.Fatal("non-npm should not match")
	}

	if err := recordQuarantineStatus(dir, "npm", "webpack-json", false); err != nil {
		t.Fatal(err)
	}
	if !HasQuarantineCacheEntry(dir, "npm", "webpack-json") {
		t.Fatal("expected negative cache entry")
	}
	if IsQuarantinedCached(dir, "npm", "webpack-json") {
		t.Fatal("expected webpack-json not quarantined")
	}

	if _, err := os.ReadFile(QuarantineCachePath(dir)); err != nil {
		t.Fatalf("cache file missing: %v", err)
	}
}

func TestRefreshNPMQuarantineCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nodemon-webpatch":
			_, _ = w.Write([]byte(`{"name":"nodemon-webpatch","versions":{"0.0.1-security":{}}}`))
		case "/webpack-json":
			_, _ = w.Write([]byte(`{"name":"webpack-json","versions":{"1.0.0":{},"0.0.1-security":{}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	orig := NPMRegistryBaseForTest()
	t.Cleanup(func() { SetNPMRegistryBaseForTest(orig) })
	SetNPMRegistryBaseForTest(srv.URL)

	dir := t.TempDir()
	RefreshNPMQuarantineCache(context.Background(), dir, "depx-test", time.Second, []string{
		"nodemon-webpatch",
		"webpack-json",
	})

	if !IsQuarantinedCached(dir, "npm", "nodemon-webpatch") {
		t.Fatal("expected nodemon-webpatch quarantined")
	}
	if IsQuarantinedCached(dir, "npm", "webpack-json") {
		t.Fatal("expected webpack-json not quarantined")
	}
	if !HasQuarantineCacheEntry(dir, "npm", "webpack-json") {
		t.Fatal("expected webpack-json cached as checked")
	}
}
