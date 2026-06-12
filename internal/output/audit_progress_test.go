package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/audit"
)

// On an interactive terminal the transient progress line is prefixed with an
// animated spinner glyph that keeps ticking between callbacks, and stop()
// clears the line.
func TestAuditProgressAnimatesInteractive(t *testing.T) {
	var buf bytes.Buffer
	ui := &auditProgressUI{
		errOut:      &buf,
		c:           Options{NoColor: true}.color(),
		interactive: true,
	}
	ui.progress("Checking packages... 10/100")
	time.Sleep(50 * time.Millisecond)
	ui.stop()

	out := buf.String()
	if !strings.Contains(out, "Checking packages... 10/100") {
		t.Fatalf("expected transient message, got %q", out)
	}
	glyphs := 0
	for _, f := range spinnerFrames {
		glyphs += strings.Count(out, f)
	}
	if glyphs == 0 {
		t.Fatalf("expected animated spinner glyphs, got %q", out)
	}
	if !strings.HasSuffix(out, "\r") {
		t.Fatalf("expected line cleared on stop, got %q", out)
	}
}

// A non-interactive reporter must not emit spinner glyphs (keeps CI logs and
// piped output clean), and stop() is a safe no-op.
func TestAuditProgressNoGlyphNonInteractive(t *testing.T) {
	var buf bytes.Buffer
	p, stop := NewAuditProgress(Options{ErrOut: &buf, NoColor: true}, false)
	p.OnQuery(10, 100, "")
	stop()

	out := buf.String()
	for _, f := range spinnerFrames {
		if strings.Contains(out, f) {
			t.Fatalf("non-interactive output should have no spinner glyph, got %q", out)
		}
	}
}

func TestAuditProgressAggregatesGitHubFetch(t *testing.T) {
	var errBuf bytes.Buffer
	o := Options{ErrOut: &errBuf, NoColor: true}
	p, _ := NewAuditProgress(o, false)

	p.OnStatus("Resolving 3 GitHub repositories…")
	p.OnStatus("Fetching SBOM from GitHub for github/dmca…")
	p.OnStatus("SBOM ready for github/dmca")
	p.OnStatus("Fetching SBOM from GitHub for github/gemoji…")
	p.OnStatus("Skipping github/choosealicense (not found)")
	p.OnStatus("Skipped 1 repositories")
	p.OnStatus("Checking dependencies in 2 lockfiles and SBOMs")

	out := errBuf.String()
	if strings.Count(out, "Fetching SBOM from GitHub for") != 0 {
		t.Fatalf("expected fetch lines aggregated, got:\n%s", out)
	}
	if !strings.Contains(out, "GitHub repos 2/3") {
		t.Fatalf("expected progress counter, got:\n%s", out)
	}
	if !strings.Contains(out, "Skipping github/choosealicense (not found)") {
		t.Fatalf("expected concise skip note, got:\n%s", out)
	}
}

func TestAuditProgressAggregatesGitHubCache(t *testing.T) {
	var errBuf bytes.Buffer
	o := Options{ErrOut: &errBuf, NoColor: true}
	p, _ := NewAuditProgress(o, false)

	for i := 0; i < 5; i++ {
		p.OnStatus("Using cached SBOM for projectdiscovery/repo" + string(rune('a'+i)))
	}
	p.OnStatus("Checking dependencies in 6 lockfiles and SBOMs")

	out := errBuf.String()
	if strings.Count(out, "Using cached SBOM for") != 0 {
		t.Fatalf("expected cached lines aggregated, got:\n%s", out)
	}
	if !strings.Contains(out, "GitHub repos: 5 cached, 0 fetched ready") {
		t.Fatalf("expected github summary, got:\n%s", out)
	}
}

func TestAuditProgressExtractSummary(t *testing.T) {
	var errBuf bytes.Buffer
	o := Options{ErrOut: &errBuf, NoColor: true}
	p, _ := NewAuditProgress(o, false)

	p.OnSource(1, 3, "/tmp/a/sbom.json", audit.SourceTypeSBOM, 10)
	p.OnSource(2, 3, "/tmp/b/sbom.json", audit.SourceTypeSBOM, 0)
	p.OnSource(3, 3, "/tmp/c/sbom.json", audit.SourceTypeSBOM, 5)

	out := errBuf.String()
	if strings.Contains(out, "[1/3]") {
		t.Fatalf("expected no per-source lines in default mode, got:\n%s", out)
	}
	if !strings.Contains(out, "Extracted 15 packages from 3 files (2 with dependencies)") {
		t.Fatalf("expected extract summary, got:\n%s", out)
	}
}

func TestAuditProgressVerboseAggregatesGitHubFetch(t *testing.T) {
	var errBuf bytes.Buffer
	o := Options{ErrOut: &errBuf, NoColor: true}
	p, _ := NewAuditProgress(o, true)

	p.OnStatus("Resolving 3 GitHub repositories…")
	p.OnStatus("Fetching SBOM from GitHub for github/dmca…")
	p.OnStatus("SBOM ready for github/dmca")
	p.OnStatus("Skipping github/choosealicense (not found)")
	p.OnStatus("Checking dependencies in 2 lockfiles and SBOMs")

	out := errBuf.String()
	if strings.Count(out, "Fetching SBOM from GitHub for") != 0 {
		t.Fatalf("expected fetch lines aggregated in verbose mode, got:\n%s", out)
	}
	if !strings.Contains(out, "GitHub repos 2/3") {
		t.Fatalf("expected github summary, got:\n%s", out)
	}
	if !strings.Contains(out, "Skipping github/choosealicense (not found)") {
		t.Fatalf("expected verbose skip detail, got:\n%s", out)
	}
}

func TestAuditProgressVerboseUsesExtractSummary(t *testing.T) {
	var errBuf bytes.Buffer
	o := Options{ErrOut: &errBuf, NoColor: true}
	p, _ := NewAuditProgress(o, true)

	p.OnSource(1, 2, "/tmp/a/sbom.json", audit.SourceTypeSBOM, 3)
	p.OnSource(2, 2, "/tmp/b/sbom.json", audit.SourceTypeSBOM, 0)

	out := errBuf.String()
	if strings.Contains(out, "[1/2]") {
		t.Fatalf("expected no per-source lines in verbose mode, got:\n%s", out)
	}
	if !strings.Contains(out, "Extracted 3 packages from 2 files (1 with dependencies)") {
		t.Fatalf("expected extract summary, got:\n%s", out)
	}
}
