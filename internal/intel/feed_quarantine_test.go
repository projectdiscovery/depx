package intel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/source"
)

func TestScheduleFeedQuarantineRefreshNonBlocking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"nodemon-webpatch","versions":{"0.0.1-security":{}}}`))
	}))
	defer srv.Close()

	orig := registry.NPMRegistryBaseForTest()
	t.Cleanup(func() { registry.SetNPMRegistryBaseForTest(orig) })
	registry.SetNPMRegistryBaseForTest(srv.URL)

	dir := t.TempDir()
	entries := []source.PackageEntry{
		{Ecosystem: "npm", Name: "nodemon-webpatch", IDs: []string{"MAL-2026-5180"}},
	}

	done := make(chan struct{})
	scheduleQuarantineRefresh = func(fn func()) {
		fn()
		close(done)
	}
	t.Cleanup(func() { scheduleQuarantineRefresh = func(fn func()) { go fn() } })

	scheduleFeedQuarantineRefresh(dir, "depx-test", time.Second, entries)
	if entries[0].Quarantined {
		t.Fatal("feed must not wait for quarantine refresh")
	}

	<-done
	if !registry.IsQuarantinedCached(dir, "npm", "nodemon-webpatch") {
		t.Fatal("expected background refresh to populate cache")
	}
}

func TestScheduleFeedQuarantineRefreshSkipsCached(t *testing.T) {
	dir := t.TempDir()
	if err := registry.SetQuarantined(dir, "npm", "nodemon-webpatch", true); err != nil {
		t.Fatal(err)
	}

	called := false
	scheduleQuarantineRefresh = func(fn func()) {
		called = true
		fn()
	}
	t.Cleanup(func() { scheduleQuarantineRefresh = func(fn func()) { go fn() } })

	scheduleFeedQuarantineRefresh(dir, "depx-test", time.Second, []source.PackageEntry{
		{Ecosystem: "npm", Name: "nodemon-webpatch"},
	})
	if called {
		t.Fatal("expected no refresh when cache already has entry")
	}
}
