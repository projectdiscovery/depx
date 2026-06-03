package source

import (
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/osv"
)

func TestEntryFromVuln(t *testing.T) {
	pub := time.Date(2026, 5, 11, 19, 23, 16, 0, time.UTC)
	mod := time.Date(2026, 5, 11, 20, 46, 16, 0, time.UTC)
	entry := EntryFromVuln(&osv.Vulnerability{
		ID:        "MAL-2026-3431",
		Summary:   "Malicious code in apkeep (PyPI)",
		Published: pub.Format(time.RFC3339),
		Modified:  mod.Format(time.RFC3339),
		Affected: []osv.Affected{{
			Package: &osv.Package{Name: "apkeep", Ecosystem: "PyPI"},
		}},
	})
	if entry.IDs[0] != "MAL-2026-3431" || entry.Name != "apkeep" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if !entry.Published.Equal(pub) || !entry.ModifiedAt.Equal(mod) {
		t.Fatalf("timestamps: pub=%v mod=%v", entry.Published, entry.ModifiedAt)
	}
	if entry.PackageURL != "https://pypi.org/project/apkeep/" {
		t.Fatalf("package url: %q", entry.PackageURL)
	}
}
