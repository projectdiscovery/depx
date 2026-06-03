package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/osv"
)

// TestDownloadPendingConcurrentEntriesNoDataRace exercises downloadPending with
// many pending entries so the worker pool writes to the shared manifest map
// concurrently. Run under `go test -race` it guards against the concurrent map
// write that previously crashed `depx github <org>` mid-sync.
func TestDownloadPendingConcurrentEntriesNoDataRace(t *testing.T) {
	cacheDir := t.TempDir()
	s := &osvSyncer{cfg: Config{
		CacheDir:  cacheDir,
		UserAgent: "depx-test",
		Timeout:   2 * time.Second,
		Source:    "osv",
	}}

	modified := time.Now().UTC().Truncate(time.Second)
	const n = 300

	m := newManifest("osv")
	pending := make([]osv.IndexEntry, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("MAL-TEST-%04d", i)
		// Pre-seed the blob cache so fetchVulnBlob resolves locally (no network).
		if err := writeVulnBlob(cacheDir, id, &osv.Vulnerability{
			ID:       id,
			Modified: modified.Format(time.RFC3339),
		}); err != nil {
			t.Fatalf("seed blob %s: %v", id, err)
		}
		m.Entries[id] = EntryRecord{Ecosystem: "npm", Modified: modified, Status: EntryPending}
		pending = append(pending, osv.IndexEntry{ID: id, Ecosystem: "npm", Modified: modified})
	}

	if err := s.downloadPending(context.Background(), m, pending, nil); err != nil {
		t.Fatalf("downloadPending: %v", err)
	}

	for _, e := range pending {
		if got := m.Entries[e.ID].Status; got != EntryReady {
			t.Fatalf("entry %s status = %q, want %q", e.ID, got, EntryReady)
		}
	}
}

// TestDownloadPendingWithdrawnNotPending verifies that an advisory withdrawn at
// the source is recorded as EntryWithdrawn (not EntryFailed) and therefore does
// not linger in the pending count forever.
func TestDownloadPendingWithdrawnNotPending(t *testing.T) {
	cacheDir := t.TempDir()
	s := &osvSyncer{cfg: Config{
		CacheDir:  cacheDir,
		UserAgent: "depx-test",
		Timeout:   2 * time.Second,
		Source:    "osv",
	}}

	modified := time.Now().UTC().Truncate(time.Second)
	m := newManifest("osv")

	const id = "MAL-WITHDRAWN-0001"
	if err := writeVulnBlob(cacheDir, id, &osv.Vulnerability{
		ID:        id,
		Modified:  modified.Format(time.RFC3339),
		Withdrawn: modified.Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("seed withdrawn blob: %v", err)
	}
	m.Entries[id] = EntryRecord{Ecosystem: "npm", Modified: modified, Status: EntryPending}
	pending := []osv.IndexEntry{{ID: id, Ecosystem: "npm", Modified: modified}}

	if err := s.downloadPending(context.Background(), m, pending, nil); err != nil {
		t.Fatalf("downloadPending: %v", err)
	}

	if got := m.Entries[id].Status; got != EntryWithdrawn {
		t.Fatalf("withdrawn entry status = %q, want %q", got, EntryWithdrawn)
	}
	if n := m.countPending(); n != 0 {
		t.Fatalf("countPending = %d, want 0 (withdrawn must not count)", n)
	}
}

func TestShouldBulkSeed(t *testing.T) {
	s := &osvSyncer{}
	m := newManifest("osv")
	pending := make([]osv.IndexEntry, 150)
	if !s.shouldBulkSeed(m, pending, 150) {
		t.Fatal("expected bulk seed on cold full catalog")
	}
	m.Sync.LastSuccess = time.Now().UTC()
	if s.shouldBulkSeed(m, pending, 150) {
		t.Fatal("expected no bulk seed after successful sync")
	}
	m.Sync.LastSuccess = time.Time{}
	if s.shouldBulkSeed(m, pending[:10], 10) {
		t.Fatal("expected no bulk seed for small catalogs")
	}
}

func TestLoadIndexBlockingSkipsPartialCompiledUntilSynced(t *testing.T) {
	cacheDir := t.TempDir()
	modified := time.Now().UTC().Truncate(time.Second)
	if err := writeVulnBlob(cacheDir, "MAL-LOCAL-1", &osv.Vulnerability{
		ID:       "MAL-LOCAL-1",
		Summary:  "Malicious code in apkeep (PyPI)",
		Modified: modified.Format(time.RFC3339),
		Affected: []osv.Affected{{
			Package: &osv.Package{Name: "apkeep", Ecosystem: "PyPI"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeVulnBlob(cacheDir, "MAL-LOCAL-2", &osv.Vulnerability{
		ID:       "MAL-LOCAL-2",
		Summary:  "Malicious code in apkeep-utils (npm)",
		Modified: modified.Format(time.RFC3339),
		Affected: []osv.Affected{{
			Package: &osv.Package{Name: "apkeep-utils", Ecosystem: "npm"},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	partial := osv.NewEmptyMaliciousIndex()
	partial.AddListing("npm", "other-pkg", "MAL-OLD-1", "old", true, nil, time.Time{}, modified)
	path := osv.CompiledCachePath(cacheDir, "compiled")
	if err := osv.SaveCompiledIndex(path, 1, partial); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DEPX_MODIFIED_INDEX_URL", "http://127.0.0.1:1/modified_id.csv")

	s := &osvSyncer{cfg: Config{
		CacheDir:           cacheDir,
		UserAgent:          "depx-test",
		Timeout:            2 * time.Second,
		Source:             "osv",
		scheduleBackground: func(fn func(context.Context)) {},
	}}

	_, err := s.loadIndex(context.Background(), false, func(loaded, total int) {}, nil)
	if err == nil {
		t.Fatal("expected blocking load to fail when sync never succeeded and catalog fetch is unavailable")
	}
}

func TestLoadIndexRebuildsFromLocalBlobsWithoutNetwork(t *testing.T) {
	cacheDir := t.TempDir()
	modified := time.Now().UTC().Truncate(time.Second)
	published := modified.Add(-24 * time.Hour)
	if err := writeVulnBlob(cacheDir, "MAL-LOCAL-1", &osv.Vulnerability{
		ID:        "MAL-LOCAL-1",
		Summary:   "Malicious code in terminal-kit (npm)",
		Published: published.Format(time.RFC3339),
		Modified:  modified.Format(time.RFC3339),
		Affected: []osv.Affected{{
			Package: &osv.Package{Name: "terminal-kit", Ecosystem: "npm"},
		}},
	}); err != nil {
		t.Fatal(err)
	}

	s := &osvSyncer{cfg: Config{
		CacheDir:  cacheDir,
		UserAgent: "depx-test",
		Timeout:   2 * time.Second,
		Source:    "osv",
		scheduleBackground: func(fn func(context.Context)) {
			// no background sync in this test
		},
	}}

	idx, err := s.loadIndex(context.Background(), false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	match := idx.Search("terminal", "", 10)
	if len(match.Hits) != 1 || match.Hits[0].Name != "terminal-kit" {
		t.Fatalf("unexpected search hits: %+v", match.Hits)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "mal", "compiled.json")); err != nil {
		t.Fatalf("expected compiled index written: %v", err)
	}
}
