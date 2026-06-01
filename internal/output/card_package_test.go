package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/check"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/source"
)

func TestWriteCheckCardIncludesPackageURL(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeCheckCard(o, check.Result{
		Ref:                 "pypi:apkeep",
		Verdict:             check.VerdictMalicious,
		IDs:                 []string{"MAL-2026-3431"},
		PackageName:         "apkeep",
		PackageEcosystem:    "PyPI",
		PackageURL:          "https://pypi.org/project/apkeep/",
		MatchedEcosystems:     []string{"PyPI"},
		CheckedEcosystems:     []string{"npm", "PyPI", "Go", "crates.io", "RubyGems", "Maven"},
		Advisories: []check.AdvisorySummary{{
			Summary: "Malicious code in apkeep (PyPI)",
		}},
	})

	out := buf.String()
	if !strings.Contains(out, "Package: https://pypi.org/project/apkeep/") {
		t.Fatalf("missing package URL in check card:\n%s", out)
	}
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

func TestWriteIDCardIncludesPackageURL(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeIDCard(o, &osv.Vulnerability{
		ID:        "MAL-2026-3431",
		Summary:   "Malicious code in apkeep (PyPI)",
		Published: "2026-05-11T19:23:16Z",
		Modified:  "2026-05-11T20:46:16.684861Z",
		Affected: []osv.Affected{{
			Package: &osv.Package{Name: "apkeep", Ecosystem: "PyPI"},
		}},
		References: []osv.Reference{{URL: "https://bad-packages.kam193.eu/pypi/package/apkeep"}},
	})

	out := buf.String()
	if !strings.Contains(out, "Package: https://pypi.org/project/apkeep/") {
		t.Fatalf("missing package URL in id card:\n%s", out)
	}
	if !strings.Contains(out, "OSV: https://osv.dev/vulnerability/MAL-2026-3431") {
		t.Fatalf("missing OSV link in id card:\n%s", out)
	}
	assertAdvisoryDetailOrder(t, out)
}

func TestWriteCheckCardMatchesIDDetailOrder(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeCheckCard(o, check.Result{
		Ref:              "pypi:apkeep",
		Verdict:          check.VerdictMalicious,
		IDs:              []string{"MAL-2026-3431"},
		PackageName:      "apkeep",
		PackageEcosystem: "PyPI",
		PackageURL:       "https://pypi.org/project/apkeep/",
		MatchedEcosystems:  []string{"PyPI"},
		CheckedEcosystems:  []string{"npm", "PyPI"},
		Advisories: []check.AdvisorySummary{{
			Summary:     "Malicious code in apkeep (PyPI)",
			URL:         "https://osv.dev/vulnerability/MAL-2026-3431",
			PublishedAt: "2026-05-11T19:23:16Z",
			ModifiedAt:  "2026-05-11T20:46:16.684861Z",
			References:  []check.AdvisoryReference{{URL: "https://bad-packages.kam193.eu/pypi/package/apkeep"}},
		}},
	})

	assertAdvisoryDetailOrder(t, buf.String())
}

func assertAdvisoryDetailOrder(t *testing.T, out string) {
	t.Helper()
	pkg := strings.Index(out, "Package:")
	pub := strings.Index(out, "Published:")
	osvLine := strings.Index(out, "OSV:")
	refs := strings.Index(out, "References:")
	if pkg < 0 || pub < 0 || osvLine < 0 || refs < 0 {
		t.Fatalf("missing expected detail lines:\n%s", out)
	}
	if !(pkg < pub && pub < osvLine && osvLine < refs) {
		t.Fatalf("expected Package → Published → OSV → References order:\n%s", out)
	}
}
