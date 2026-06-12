package source

import (
	"testing"
	"time"
)

func TestFilterPackageEntriesByFeedTime(t *testing.T) {
	since := time.Now().UTC().Add(-72 * time.Hour)
	entries := []PackageEntry{
		{IDs: []string{"MAL-NEW"}, Published: time.Now().UTC().Add(-24 * time.Hour)},
		{IDs: []string{"MAL-OLD"}, Published: time.Now().UTC().Add(-10 * 24 * time.Hour)},
		{IDs: []string{"MAL-MOD-ONLY"}, ModifiedAt: time.Now().UTC()},
	}
	out := FilterPackageEntriesByFeedTime(entries, since)
	if len(out) != 1 || out[0].IDs[0] != "MAL-NEW" {
		t.Fatalf("expected only recently published entry, got %+v", out)
	}
}

func TestSortPackageEntriesByPublished(t *testing.T) {
	older := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	entries := []PackageEntry{
		{
			Name:       "stale-modified",
			IDs:        []string{"MAL-OLD-MOD"},
			Published:  older,
			ModifiedAt: time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			Name:       "fresh-published",
			IDs:        []string{"MAL-NEW-PUB"},
			Published:  newer,
			ModifiedAt: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		},
	}

	SortPackageEntriesByPublished(entries)
	if entries[0].IDs[0] != "MAL-NEW-PUB" {
		t.Fatalf("want newest published first, got %q then %q", entries[0].IDs[0], entries[1].IDs[0])
	}
}
