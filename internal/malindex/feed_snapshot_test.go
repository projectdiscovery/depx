package malindex

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPublishedFeedSnapshotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	compiledPath := CompiledCachePath(dir, "compiled")
	now := time.Now().UTC()
	idx := &MaliciousIndex{byPackage: map[string][]malPackageVuln{}}
	addListing(idx, "npm", "evil-pkg", "MAL-1", "bad pkg", true, nil,
		now.Add(-2*24*time.Hour), now.Add(-24*time.Hour))
	addListing(idx, "pypi", "old-pkg", "MAL-2", "old", true, nil,
		now.Add(-60*24*time.Hour), now.Add(-59*24*time.Hour))

	if err := SaveCompiledIndex(compiledPath, 2, idx); err != nil {
		t.Fatalf("SaveCompiledIndex: %v", err)
	}

	hits, ok := LoadPublishedFeedSnapshot(dir, compiledPath)
	if !ok {
		t.Fatal("expected snapshot after SaveCompiledIndex")
	}
	if len(hits) != 1 || hits[0].Name != "evil-pkg" {
		t.Fatalf("got %d hits, want 1 recent hit: %+v", len(hits), hits)
	}

	since := time.Now().UTC().Add(-7 * 24 * time.Hour)
	filtered := FilterFeedHits(hits, since, "")
	if len(filtered) != 1 || filtered[0].Name != "evil-pkg" {
		t.Fatalf("FilterFeedHits: %+v", filtered)
	}

	// Invalidate snapshot when compiled file changes.
	if err := os.WriteFile(compiledPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := LoadPublishedFeedSnapshot(dir, compiledPath); ok {
		t.Fatal("expected snapshot invalid after compiled modtime change")
	}
}

func TestWritePublishedFeedSnapshotPath(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "feed", "published_snapshot.json")
	if got := PublishedFeedSnapshotPath(dir); got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}
