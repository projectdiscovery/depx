package malindex

import (
	"fmt"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/inventory"
)

// addListing indexes a single malicious package for tests, mirroring the data
// the inventory export carries.
func addListing(idx *MaliciousIndex, eco, name, id, summary string, allVersions bool, versions []string, published, modified time.Time) {
	idx.AddRecord(inventory.Record{
		Ecosystem:        eco,
		Name:             name,
		IDs:              []string{id},
		Summary:          summary,
		AllVersions:      allVersions,
		AffectedVersions: versions,
		PublishedAt:      published,
		ModifiedAt:       modified,
	})
}

func TestMaliciousIndexMatch(t *testing.T) {
	idx := &MaliciousIndex{byPackage: map[string][]malPackageVuln{}}
	idx.addVuln(&Vulnerability{
		ID:      "MAL-TEST-1",
		Summary: "Malicious evil-pkg",
		Affected: []Affected{{
			Package: &Package{Name: "evil-pkg", Ecosystem: "npm"},
		}},
	})
	idx.addVuln(&Vulnerability{
		ID:      "MAL-TEST-2",
		Summary: "Malicious lodash version",
		Affected: []Affected{{
			Package:  &Package{Name: "lodash", Ecosystem: "npm"},
			Versions: []string{"4.17.20"},
		}},
	})

	if m := idx.Match("npm", "lodash", "4.17.21"); len(m) != 0 {
		t.Fatalf("expected clean lodash, got %+v", m)
	}
	if m := idx.Match("npm", "lodash", "4.17.20"); len(m) != 1 || m[0].ID != "MAL-TEST-2" {
		t.Fatalf("expected lodash hit, got %+v", m)
	}
	if m := idx.Match("npm", "evil-pkg", "9.9.9"); len(m) != 1 || m[0].ID != "MAL-TEST-1" {
		t.Fatalf("expected any-version hit, got %+v", m)
	}
	if m := idx.Match("PyPI", "apkeep", "1.0.0"); len(m) != 0 {
		t.Fatalf("expected clean unknown package, got %+v", m)
	}
}

func TestMaliciousIndexSearch(t *testing.T) {
	idx := &MaliciousIndex{byPackage: map[string][]malPackageVuln{}}
	addListing(idx, "npm", "apkeep-utils", "MAL-TEST-4", "bad apkeep", true, nil, time.Time{}, time.Time{})
	addListing(idx, "PyPI", "apkeep", "MAL-TEST-5", "bad apkeep pypi", true, nil, time.Time{}, time.Time{})

	match := idx.Search("apkeep", "", 10)
	if len(match.Hits) != 2 || match.Total != 2 {
		t.Fatalf("expected 2 hits, got %d (total %d): %+v", len(match.Hits), match.Total, match.Hits)
	}
	match = idx.Search("apkeep", "npm", 10)
	if len(match.Hits) != 1 || match.Hits[0].Name != "apkeep-utils" {
		t.Fatalf("expected npm-only hit, got %+v", match.Hits)
	}
}

func TestMaliciousIndexSearchTotalBeforeLimit(t *testing.T) {
	idx := &MaliciousIndex{byPackage: map[string][]malPackageVuln{}}
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("chat-pkg-%02d", i)
		addListing(idx, "npm", name, fmt.Sprintf("MAL-CHAT-%02d", i), "bad", true, nil, time.Time{}, time.Now().UTC().Add(-time.Duration(i)*time.Hour))
	}

	match := idx.Search("chat", "", 10)
	if match.Total != 30 {
		t.Fatalf("expected total 30 matches, got %d", match.Total)
	}
	if len(match.Hits) != 10 {
		t.Fatalf("expected 10 capped hits, got %d", len(match.Hits))
	}
}

func TestMaliciousIndexListSincePublished(t *testing.T) {
	idx := &MaliciousIndex{}
	recentPub := time.Now().UTC().Add(-24 * time.Hour)
	oldPub := time.Now().UTC().Add(-20 * 24 * time.Hour)
	recentMod := time.Now().UTC()
	addListing(idx, "npm", "fresh", "MAL-FRESH", "fresh", true, nil, recentPub, recentMod)
	addListing(idx, "npm", "stale", "MAL-STALE", "stale", true, nil, oldPub, recentMod)

	since := time.Now().UTC().Add(-72 * time.Hour)
	hits := idx.ListSincePublished(since, "")
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit in published window, got %d: %+v", len(hits), hits)
	}
	if hits[0].IDs[0] != "MAL-FRESH" {
		t.Fatalf("unexpected hit: %+v", hits[0])
	}
}

func TestMaliciousIndexLookupByID(t *testing.T) {
	idx := &MaliciousIndex{}
	addListing(idx, "npm", "evil-pkg", "MAL-TEST-1", "bad pkg", true, nil, time.Time{}, time.Time{})

	hit, ok := idx.LookupByID("MAL-TEST-1")
	if !ok {
		t.Fatal("expected lookup hit")
	}
	if hit.Name != "evil-pkg" || hit.Ecosystem != "npm" {
		t.Fatalf("unexpected hit: %+v", hit)
	}
	if _, ok := idx.LookupByID("MAL-MISSING"); ok {
		t.Fatal("expected miss for unknown id")
	}
}

func TestAddListingCarriesTimestamps(t *testing.T) {
	idx := &MaliciousIndex{}
	published := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	modified := time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC)
	addListing(idx, "npm", "evil-pkg", "MAL-TEST-3", "bad pkg", true, nil, published, modified)

	matches := idx.Match("npm", "evil-pkg", "1.0.0")
	if len(matches) != 1 {
		t.Fatalf("expected one match, got %+v", matches)
	}
	if !matches[0].Published.Equal(published) {
		t.Fatalf("published = %v want %v", matches[0].Published, published)
	}
	if !matches[0].Modified.Equal(modified) {
		t.Fatalf("modified = %v want %v", matches[0].Modified, modified)
	}
}

// TestAddRecordNoVersionCoverage guards the fsevents-style false positive: the
// export drops upstream OSV ranges, so a ranged advisory arrives as
// all_versions=false with an empty affected_versions list. Such a record must
// stay discoverable by name/ID but must not flag any pinned version.
func TestAddRecordNoVersionCoverage(t *testing.T) {
	idx := &MaliciousIndex{}
	// all_versions=false, no affected_versions (the ambiguous bucket).
	addListing(idx, "npm", "fsevents", "MAL-2023-462", "Malicious code in fsevents", false, nil, time.Time{}, time.Time{})

	if got := idx.Match("npm", "fsevents", "2.1.3"); len(got) != 0 {
		t.Fatalf("pinned version must not match without version coverage, got %+v", got)
	}
	if got := idx.QueryLocal("npm", "fsevents", "2.1.3"); len(got) != 0 {
		t.Fatalf("QueryLocal pinned version must not match, got %+v", got)
	}
	if got := idx.QueryLocal("npm", "fsevents", ""); len(got) != 1 {
		t.Fatalf("bare-name lookup must still surface the advisory, got %+v", got)
	}
	if _, ok := idx.LookupByID("MAL-2023-462"); !ok {
		t.Fatal("advisory must remain discoverable by ID")
	}
}

// TestAddRecordAllVersions confirms an explicit all_versions=true record still
// matches every version.
func TestAddRecordAllVersions(t *testing.T) {
	idx := &MaliciousIndex{}
	addListing(idx, "npm", "all-bad", "MAL-ALL", "every version bad", true, nil, time.Time{}, time.Time{})
	if got := idx.Match("npm", "all-bad", "9.9.9"); len(got) != 1 {
		t.Fatalf("all_versions=true must match any version, got %+v", got)
	}
}

// TestVulnLookupCaseInsensitive confirms advisory IDs resolve regardless of the
// caller's casing, while output echoes the canonical (stored) form.
func TestVulnLookupCaseInsensitive(t *testing.T) {
	idx := &MaliciousIndex{}
	addListing(idx, "npm", "evil-pkg", "MAL-2026-5682", "bad package", true, nil, time.Time{}, time.Time{})

	for _, q := range []string{"MAL-2026-5682", "mal-2026-5682", "Mal-2026-5682"} {
		v, ok := idx.Vuln(q)
		if !ok {
			t.Fatalf("Vuln(%q) not found", q)
		}
		if v.ID != "MAL-2026-5682" {
			t.Fatalf("Vuln(%q) returned canonical ID %q, want MAL-2026-5682", q, v.ID)
		}
	}

	if _, ok := idx.Vuln("MAL-0000-0000"); ok {
		t.Fatal("unknown advisory must not resolve")
	}
}

func TestSemverInRange(t *testing.T) {
	r := Range{
		Type: "SEMVER",
		Events: []Event{
			{Introduced: "0"},
			{Fixed: "2.0.0"},
		},
	}
	if !versionInRange("1.5.0", r) {
		t.Fatal("expected 1.5.0 in range")
	}
	if versionInRange("2.0.0", r) {
		t.Fatal("expected 2.0.0 out of range")
	}
}
