package source

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CountBucket is a labeled count with optional share (0–100).
type CountBucket struct {
	Label string  `json:"label"`
	Count int     `json:"count"`
	Share float64 `json:"share_percent,omitempty"`
}

// WindowStats aggregates feed entries in the active --since window.
type WindowStats struct {
	Advisories     int           `json:"advisories"`
	UniquePackages int           `json:"unique_packages"`
	Ecosystems     []CountBucket `json:"ecosystems,omitempty"`
	Namespaces     []CountBucket `json:"namespaces,omitempty"`
	Age            []CountBucket `json:"age,omitempty"`
	Withdrawn      int           `json:"withdrawn"`
	WithAliases    int           `json:"with_aliases"`
}

// CorpusStats describes the local malicious-package index snapshot.
type CorpusStats struct {
	Source          string `json:"source,omitempty"`
	IndexedPackages int    `json:"indexed_packages,omitempty"`
	LastSync        string `json:"last_sync,omitempty"`
	PendingSync     int    `json:"pending_sync,omitempty"`
}

// ComputeWindowStats builds dashboard metrics from all entries in the feed window.
func ComputeWindowStats(entries []PackageEntry) WindowStats {
	st := WindowStats{Advisories: len(entries)}
	if len(entries) == 0 {
		return st
	}

	seenPkg := make(map[string]struct{})
	ecoCounts := make(map[string]int)
	nsCounts := make(map[string]int)
	nsTotal := 0
	var day1, day3, day7, olderCount int

	for _, e := range entries {
		key := packageKey(e)
		if key != "" {
			seenPkg[key] = struct{}{}
		}
		eco := strings.TrimSpace(e.Ecosystem)
		if eco == "" {
			eco = "unknown"
		}
		ecoCounts[eco]++

		if ns := namespaceKey(e.Ecosystem, e.Name); ns != "" {
			nsCounts[ns]++
			nsTotal++
		}

		if e.Withdrawn {
			st.Withdrawn++
		}
		if len(e.Aliases) > 0 {
			st.WithAliases++
		}

		switch ageBucket(feedSortTime(e)) {
		case "day1":
			day1++
		case "day3":
			day3++
		case "day7":
			day7++
		default:
			olderCount++
		}
	}

	st.UniquePackages = len(seenPkg)
	st.Ecosystems = topBuckets(ecoCounts, 5, len(entries))
	st.Namespaces = topBuckets(nsCounts, 5, nsTotal)
	st.Age = []CountBucket{
		bucket("last 24h", day1, len(entries)),
		bucket("2-3 days", day3, len(entries)),
		bucket("4-7 days", day7, len(entries)),
		bucket("older (>7d)", olderCount, len(entries)),
	}
	return st
}

func packageKey(e PackageEntry) string {
	name := strings.TrimSpace(e.Name)
	eco := strings.TrimSpace(e.Ecosystem)
	switch {
	case name == "" && eco == "":
		return ""
	case name == "":
		return eco
	default:
		return eco + "/" + name
	}
}

// namespaceKey derives the scope/org a package belongs to, per ecosystem
// conventions. Returns "" when a package has no meaningful namespace (e.g. an
// unscoped npm package) so callers can exclude it from "most impacted" rollups.
func namespaceKey(eco, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	switch eco := strings.ToLower(strings.TrimSpace(eco)); {
	case strings.HasPrefix(eco, "npm"):
		if strings.HasPrefix(name, "@") {
			if i := strings.IndexByte(name, '/'); i > 0 {
				return name[:i]
			}
			return name
		}
		return ""
	case strings.HasPrefix(eco, "go"):
		parts := strings.Split(name, "/")
		if len(parts) >= 3 && strings.Contains(parts[0], ".") {
			return parts[0] + "/" + parts[1]
		}
		if len(parts) >= 2 && strings.Contains(parts[0], ".") {
			return parts[0]
		}
		return ""
	case strings.HasPrefix(eco, "maven"):
		if i := strings.IndexByte(name, ':'); i > 0 {
			return name[:i]
		}
		return ""
	default:
		// Ecosystems without real namespaces (PyPI, RubyGems, NuGet, …) fall
		// through here. Only treat path/qualifier-style names (e.g. Composer's
		// vendor/package) as namespaced; a bare PyPI name like "discord-ban"
		// must NOT be split on "-" into a pseudo-scope.
		if i := strings.LastIndex(name, "/"); i > 0 {
			return name[:i]
		}
		if i := strings.IndexByte(name, ':'); i > 0 {
			return name[:i]
		}
		return ""
	}
}

func ageBucket(t time.Time) string {
	if t.IsZero() {
		return "older"
	}
	days := int(time.Since(t.UTC()).Hours() / 24)
	if days < 0 {
		days = 0
	}
	switch {
	case days <= 1:
		return "day1"
	case days <= 3:
		return "day3"
	case days <= 7:
		return "day7"
	default:
		return "older"
	}
}

func bucket(label string, count, total int) CountBucket {
	b := CountBucket{Label: label, Count: count}
	if total > 0 {
		b.Share = float64(count) * 100 / float64(total)
	}
	return b
}

func topBuckets(counts map[string]int, limit, total int) []CountBucket {
	type kv struct {
		key   string
		count int
	}
	items := make([]kv, 0, len(counts))
	for k, v := range counts {
		items = append(items, kv{k, v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].key < items[j].key
	})
	if limit > len(items) {
		limit = len(items)
	}
	out := make([]CountBucket, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, bucket(items[i].key, items[i].count, total))
	}
	return out
}

// FormatShare returns a short percent string for display.
func FormatShare(share float64) string {
	if share < 0.1 && share > 0 {
		return "<0.1%"
	}
	return fmt.Sprintf("%.1f%%", share)
}
