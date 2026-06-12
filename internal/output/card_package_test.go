package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/check"
	"github.com/projectdiscovery/depx/internal/malindex"
	"github.com/projectdiscovery/depx/internal/source"
)

func TestWriteCheckCardIncludesPackageURL(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeCheckCard(o, check.Result{
		Ref:               "pypi:apkeep",
		Verdict:           check.VerdictMalicious,
		IDs:               []string{"MAL-2026-3431"},
		PackageName:       "apkeep",
		PackageEcosystem:  "PyPI",
		PackageURL:        "https://pypi.org/project/apkeep/",
		MatchedEcosystems: []string{"PyPI"},
		CheckedEcosystems: []string{"npm", "PyPI", "Go", "crates.io", "RubyGems", "Maven"},
		Advisories: []check.AdvisorySummary{{
			Summary:     "Malicious code in apkeep (PyPI)",
			PublishedAt: "2026-05-11T19:23:16Z",
			ModifiedAt:  "2026-05-11T20:46:16.684861Z",
		}},
	})

	out := buf.String()
	if !strings.Contains(out, "Package: https://pypi.org/project/apkeep/") {
		t.Fatalf("missing package URL in check card:\n%s", out)
	}
	if !strings.Contains(out, "[MAL-2026-3431]") || !strings.Contains(out, "MALICIOUS") || !strings.Contains(out, "apkeep (PyPI)") {
		t.Fatalf("expected feed-style header:\n%s", out)
	}
	if strings.Contains(out, "Critical") || strings.Contains(out, "Matched:") {
		t.Fatalf("malicious check must use feed card, not legacy check layout:\n%s", out)
	}
	assertFeedCardDetailOrder(t, out)
}

func TestWriteFeedCardIncludesPackageURL(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeFeedCard(o, source.PackageEntry{
		Ecosystem:  "PyPI",
		Name:       "apkeep",
		PackageURL: "https://pypi.org/project/apkeep/",
		IDs:        []string{"MAL-2026-3431"},
		Summary:    "Malicious code in apkeep (PyPI)",
		ModifiedAt: time.Date(2026, 5, 11, 20, 46, 16, 0, time.UTC),
	})

	out := buf.String()
	if !strings.Contains(out, "Package: https://pypi.org/project/apkeep/") {
		t.Fatalf("missing package URL in feed card:\n%s", out)
	}
}

func TestWriteFeedCardHeaderOnlyListMode(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeFeedCardHeaderOnly(o, source.PackageEntry{
		Ecosystem:  "npm",
		Name:       "apka-papa-chand",
		PackageURL: "https://www.npmjs.com/package/apka-papa-chand",
		IDs:        []string{"MAL-2023-8169"},
		Summary:    "Malicious code in apka-papa-chand (npm)",
		Published:  time.Date(2023, 9, 20, 0, 0, 0, 0, time.UTC),
		ModifiedAt: time.Date(2023, 9, 21, 0, 0, 0, 0, time.UTC),
	})

	out := buf.String()
	if !strings.Contains(out, "[MAL-2023-8169]") || !strings.Contains(out, "apka-papa-chand") || !strings.Contains(out, "(npm)") {
		t.Fatalf("expected header line content:\n%s", out)
	}
	if strings.Contains(out, "Published:") || strings.Contains(out, "OSV:") || strings.Contains(out, "Package:") {
		t.Fatalf("list mode must omit detail lines:\n%s", out)
	}
	if n := strings.Count(strings.TrimSpace(out), "\n"); n != 0 {
		t.Fatalf("expected a single line, got %d newlines:\n%s", n, out)
	}
}

func TestWriteIDCardIncludesPackageURL(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeIDCard(o, &malindex.Vulnerability{
		ID:        "MAL-2026-3431",
		Summary:   "Malicious code in apkeep (PyPI)",
		Published: "2026-05-11T19:23:16Z",
		Modified:  "2026-05-11T20:46:16.684861Z",
		Affected: []malindex.Affected{{
			Package: &malindex.Package{Name: "apkeep", Ecosystem: "PyPI"},
		}},
		References: []malindex.Reference{{URL: "https://bad-packages.kam193.eu/pypi/package/apkeep"}},
	})

	out := buf.String()
	if !strings.Contains(out, "Package: https://pypi.org/project/apkeep/") {
		t.Fatalf("missing package URL in id card:\n%s", out)
	}
	if !strings.Contains(out, "OSV: https://osv.dev/vulnerability/MAL-2026-3431") {
		t.Fatalf("missing OSV link in id card:\n%s", out)
	}
	assertFeedCardDetailOrder(t, out)
}

func TestWriteCheckCardMatchesFeedCardFormat(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeCheckCard(o, check.Result{
		Ref:               "pypi:apkeep",
		Verdict:           check.VerdictMalicious,
		IDs:               []string{"MAL-2026-3431"},
		PackageName:       "apkeep",
		PackageEcosystem:  "PyPI",
		PackageURL:        "https://pypi.org/project/apkeep/",
		MatchedEcosystems: []string{"PyPI"},
		CheckedEcosystems: []string{"npm", "PyPI"},
		Advisories: []check.AdvisorySummary{{
			Summary:     "Malicious code in apkeep (PyPI)",
			URL:         "https://osv.dev/vulnerability/MAL-2026-3431",
			PublishedAt: "2026-05-11T19:23:16Z",
			ModifiedAt:  "2026-05-11T20:46:16.684861Z",
			References:  []check.AdvisoryReference{{URL: "https://bad-packages.kam193.eu/pypi/package/apkeep"}},
		}},
	})

	assertFeedCardDetailOrder(t, buf.String())
}

func TestWriteCheckCardQuarantinedIncludesDetails(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeCheckCard(o, check.Result{
		Ref:              "npm:nodemon-webpatch",
		Verdict:          check.VerdictQuarantined,
		IDs:              []string{"MAL-2026-5180"},
		PackageName:      "nodemon-webpatch",
		PackageEcosystem: "npm",
		PackageURL:       "https://www.npmjs.com/package/nodemon-webpatch",
		Advisories: []check.AdvisorySummary{{
			Summary:     "Malicious code in nodemon-webpatch (npm)",
			PublishedAt: "2026-06-03T00:00:00Z",
			ModifiedAt:  "2026-06-03T02:00:00Z",
		}},
	})

	out := buf.String()
	for _, want := range []string{
		"[MAL-2026-5180]",
		"QUARANTINED",
		"nodemon-webpatch",
		"(npm)",
		"Package: https://www.npmjs.com/package/nodemon-webpatch",
		"OSV: https://osv.dev/vulnerability/MAL-2026-5180",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	assertFeedCardDetailOrder(t, out)
}

func TestWriteFeedCardQuarantinedIncludesDetails(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	published := time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)
	modified := published.Add(2 * time.Hour)
	writeFeedCard(o, source.PackageEntry{
		Ecosystem:   "npm",
		Name:        "nodemon-webpatch",
		PackageURL:  "https://www.npmjs.com/package/nodemon-webpatch",
		IDs:         []string{"MAL-2026-5180"},
		Published:   published,
		ModifiedAt:  modified,
		Quarantined: true,
	})

	out := buf.String()
	for _, want := range []string{
		"QUARANTINED",
		"nodemon-webpatch",
		"Package: https://www.npmjs.com/package/nodemon-webpatch",
		"OSV: https://osv.dev/vulnerability/MAL-2026-5180",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	assertFeedCardDetailOrder(t, out)
}

func assertFeedCardDetailOrder(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "Published:") || strings.Contains(out, "Modified:") {
		t.Fatalf("Published/Modified line should be omitted (age is in header):\n%s", out)
	}
	if strings.Contains(out, "Withdrawn:") {
		t.Fatalf("Withdrawn line should be omitted from card:\n%s", out)
	}
	pkg := strings.Index(out, "Package:")
	osvLine := strings.Index(out, "OSV:")
	if pkg < 0 || osvLine < 0 {
		t.Fatalf("missing expected detail lines:\n%s", out)
	}
	if pkg >= osvLine {
		t.Fatalf("expected Package → OSV order:\n%s", out)
	}
}
