package osv

import (
	"fmt"
	"testing"
	"time"
)

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
	idx.AddListing("npm", "apkeep-utils", "MAL-TEST-4", "bad apkeep", true, nil, time.Time{}, time.Time{})
	idx.AddListing("PyPI", "apkeep", "MAL-TEST-5", "bad apkeep pypi", true, nil, time.Time{}, time.Time{})

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
		idx.AddListing("npm", name, fmt.Sprintf("MAL-CHAT-%02d", i), "bad", true, nil, time.Time{}, time.Now().UTC().Add(-time.Duration(i)*time.Hour))
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
	idx.AddListing("npm", "fresh", "MAL-FRESH", "fresh", true, nil, recentPub, recentMod)
	idx.AddListing("npm", "stale", "MAL-STALE", "stale", true, nil, oldPub, recentMod)

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
	idx.AddListing("npm", "evil-pkg", "MAL-TEST-1", "bad pkg", true, nil, time.Time{}, time.Time{})

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
	idx.AddListing("npm", "evil-pkg", "MAL-TEST-3", "bad pkg", true, nil, published, modified)

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
