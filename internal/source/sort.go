package source

import (
	"sort"
	"time"
)

// FeedTime is the disclosure timestamp used for --since filtering, sorting, dashboard
// age buckets, and card header badges (published date only).
func FeedTime(e PackageEntry) time.Time {
	if !e.Published.IsZero() {
		return e.Published.UTC()
	}
	return time.Time{}
}

func feedSortTime(e PackageEntry) time.Time {
	return FeedTime(e)
}

// InFeedWindow reports whether e was published on or after since.
func InFeedWindow(e PackageEntry, since time.Time) bool {
	t := FeedTime(e)
	return !t.IsZero() && !t.Before(since)
}

// FilterPackageEntriesByFeedTime keeps entries published within the active window.
func FilterPackageEntriesByFeedTime(entries []PackageEntry, since time.Time) []PackageEntry {
	if since.IsZero() {
		return entries
	}
	out := make([]PackageEntry, 0, len(entries))
	for _, e := range entries {
		if InFeedWindow(e, since) {
			out = append(out, e)
		}
	}
	return out
}

// SortPackageEntriesByPublished sorts entries newest-published-first.
func SortPackageEntriesByPublished(entries []PackageEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return feedSortTime(entries[i]).After(feedSortTime(entries[j]))
	})
}
