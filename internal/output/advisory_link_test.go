package output

import (
	"bytes"
	"strings"
	"testing"
)

// osv-hosted ids link to osv.dev under the "Source" label.
func TestAdvisoryLinkLineOSVHosted(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeAdvisoryLinkLine(o, o.color(), "MAL-2026-1234", []string{"GHSA-xxxx-yyyy-zzzz"}, "ossf")
	out := buf.String()
	if !strings.Contains(out, "Source: https://osv.dev/vulnerability/MAL-2026-1234") {
		t.Fatalf("expected osv.dev link under Source label:\n%s", out)
	}
	if !strings.Contains(out, "Aliases: GHSA-xxxx-yyyy-zzzz") {
		t.Fatalf("expected aliases appended:\n%s", out)
	}
}

// GHSCAN-MAL synthetics have no osv.dev page: show the origin feed name as text.
func TestAdvisoryLinkLineSyntheticShowsSource(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeAdvisoryLinkLine(o, o.color(), "GHSCAN-MAL-abc123", nil, "x-osint")
	out := buf.String()
	if !strings.Contains(out, "Source: x-osint") {
		t.Fatalf("expected 'Source: x-osint':\n%s", out)
	}
	if strings.Contains(out, "osv.dev") {
		t.Fatalf("synthetic id must not link to osv.dev:\n%s", out)
	}
}

// A synthetic id with no known source prints no Source line (only aliases, if any).
func TestAdvisoryLinkLineSyntheticNoSource(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	writeAdvisoryLinkLine(o, o.color(), "GHSCAN-MAL-def456", nil, "")
	if out := buf.String(); strings.Contains(out, "Source:") {
		t.Fatalf("expected no Source line when url and source are empty:\n%s", out)
	}
}
