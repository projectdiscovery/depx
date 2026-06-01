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
	if !strings.Contains(out, "Age:") {
		t.Fatalf("missing Age header:\n%s", out)
	}
	if !strings.Contains(out, "Published: "+now.Add(-72*time.Hour).Format("2006-01-02")+" (") {
		t.Fatalf("expected published date with relative age:\n%s", out)
	}
	if !strings.Contains(out, "Imported: "+now.Add(-96*time.Hour).Format("2006-01-02")+" (") {
		t.Fatalf("expected imported date with relative age:\n%s", out)
	}
}
