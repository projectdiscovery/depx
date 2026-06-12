package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/source"
)

func TestFormatTimestampWithAge(t *testing.T) {
	published := time.Now().UTC().Add(-72 * time.Hour).Truncate(24 * time.Hour)
	got := formatTimestampWithAge(published)
	wantDate := published.Format("2006-01-02")
	if !strings.HasPrefix(got, wantDate+" (") {
		t.Fatalf("expected date prefix %q in %q", wantDate, got)
	}
	if !strings.Contains(got, "(3d)") && !strings.Contains(got, "(2d)") {
		t.Fatalf("expected ~3d age in %q", got)
	}

	recent := time.Now().UTC().Add(-5 * time.Hour)
	got = formatTimestampWithAge(recent)
	if !strings.Contains(got, "(5h)") && !strings.Contains(got, "(4h)") {
		t.Fatalf("expected hours instead of 0d for same-day age, got %q", got)
	}
	if strings.Contains(got, "(0d)") {
		t.Fatalf("expected no 0d suffix, got %q", got)
	}
}

func TestFormatRelativeAge(t *testing.T) {
	now := time.Now().UTC()
	if got := formatRelativeAge(now.Add(-6 * time.Hour)); got != "6h" && got != "5h" {
		t.Fatalf("same-day age = %q, want hours", got)
	}
	if got := formatRelativeAge(now.Add(-48 * time.Hour)); got != "2d" {
		t.Fatalf("48h age = %q, want 2d", got)
	}
	if got := formatAgeUrgency(now.Add(-3 * time.Hour)); got != "3h (NEW)" && got != "2h (NEW)" {
		t.Fatalf("urgency label = %q, want Xh (NEW)", got)
	}
}

func TestFormatOSVTimeWithAge(t *testing.T) {
	got := formatOSVTimeWithAge("2026-05-28T00:00:00Z")
	if !strings.HasPrefix(got, "2026-05-28 (") || !strings.HasSuffix(got, "d)") {
		t.Fatalf("unexpected format: %q", got)
	}
	if formatOSVTimeWithAge("") != "unknown" {
		t.Fatal("expected unknown for empty time")
	}
}

func TestWriteFeedCardUsesAgeLabelAndRelativeTimestamps(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	now := time.Now().UTC()
	writeFeedCard(o, source.PackageEntry{
		Ecosystem:  "PyPI",
		Name:       "apkeep",
		PackageURL: "https://pypi.org/project/apkeep/",
		IDs:        []string{"MAL-2026-3431"},
		Summary:    "Malicious code in apkeep (PyPI)",
		Published:  now.Add(-72 * time.Hour),
		ModifiedAt: now.Add(-24 * time.Hour),
		ImportedAt: now.Add(-96 * time.Hour),
	})

	out := buf.String()
	if strings.Contains(out, "Vuln Age:") {
		t.Fatalf("expected Age label, got Vuln Age:\n%s", out)
	}
	if strings.Contains(out, "Priority:") {
		t.Fatalf("removed boilerplate priority line:\n%s", out)
	}
	if !strings.Contains(out, "apkeep") || !strings.Contains(out, "(PyPI)") {
		t.Fatalf("expected package in card header:\n%s", out)
	}
	if strings.Contains(out, "Published:") || strings.Contains(out, "Modified:") || strings.Contains(out, "Imported:") {
		t.Fatalf("timestamp line should be omitted (age is in header):\n%s", out)
	}
	if strings.Contains(out, "Ecosystem:") {
		t.Fatalf("ecosystem is in card header, not a detail line:\n%s", out)
	}
	if strings.Contains(out, "Withdrawn:") {
		t.Fatalf("withdrawn line should be omitted from card:\n%s", out)
	}
	if !strings.Contains(out, "OSV:") {
		t.Fatalf("expected OSV on last detail line:\n%s", out)
	}
	if strings.Contains(out, "Campaign:") {
		t.Fatalf("campaign removed from feed card:\n%s", out)
	}
}
