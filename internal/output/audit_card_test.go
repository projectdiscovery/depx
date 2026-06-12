package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/projectdiscovery/depx/internal/check"
)

func TestWriteAuditFindingCard(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	published := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	modified := time.Now().UTC().Add(-24 * time.Hour)
	writeAuditFindingCard(o, audit.Finding{
		Verdict:    "malicious",
		Ecosystem:  "npm",
		Name:       "evil-pkg",
		Version:    "1.2.3",
		IDs:        []string{"MAL-2026-TEST"},
		Summary:    "Malicious code in evil-pkg (npm)",
		Published:  published,
		ModifiedAt: modified,
		Lockfile:   "/tmp/project/package-lock.json",
		Source:     "/tmp/project/package-lock.json",
		SourceType: "lockfile",
		ProjectDir: "/tmp/project",
		ProjectURL: "file:///tmp/project",
		PackageURL: "https://www.npmjs.com/package/evil-pkg",
	})

	out := buf.String()
	for _, want := range []string{
		"[MAL-2026-TEST]",
		"MALICIOUS",
		"evil-pkg",
		"(npm)",
		"Lockfile: /tmp/project/package-lock.json",
		"Dependency: npm/evil-pkg@1.2.3",
		"OSV:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestWriteAuditFindingCardQuarantined(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	published := time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC)
	modified := published.Add(2 * time.Hour)
	writeAuditFindingCard(o, audit.Finding{
		Verdict:    check.VerdictQuarantined,
		Ecosystem:  "npm",
		Name:       "nodemon-webpatch",
		Version:    "1.0.0",
		IDs:        []string{"MAL-2026-5180"},
		Published:  published,
		ModifiedAt: modified,
		Lockfile:   "/tmp/project/package-lock.json",
		Source:     "/tmp/project/package-lock.json",
		PackageURL: "https://www.npmjs.com/package/nodemon-webpatch",
	})

	out := buf.String()
	for _, want := range []string{
		"[MAL-2026-5180]",
		"QUARANTINED",
		"Lockfile:",
		"Dependency:",
		"Package: https://www.npmjs.com/package/nodemon-webpatch",
		"OSV:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRenderAuditUsesFeedStyleCards(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	result := &audit.Result{
		Summary:    audit.Summary{Lockfiles: 2, Total: 10, Malicious: 1, Clean: 9},
		DurationMS: 500,
		Findings: []audit.Finding{{
			Ecosystem:  "npm",
			Name:       "evil",
			Version:    "1.0.0",
			IDs:        []string{"MAL-2026-TEST"},
			Summary:    "Malicious code in evil (npm)",
			Lockfile:   "/tmp/package-lock.json",
			ProjectDir: "/tmp",
			ProjectURL: "file:///tmp",
			PackageURL: "https://www.npmjs.com/package/evil",
		}},
	}
	if err := RenderAudit(o, "test", result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Audit results",
		"Verdict:",
		"MALICIOUS (1)",
		"Files:",
		"Dependencies:",
		"Duration:",
		"[MAL-2026-TEST]",
		"Lockfile: /tmp/package-lock.json",
		"↳ 1 malicious finding",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRenderAuditCleanResults(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	result := &audit.Result{
		Paths:      []string{"google"},
		Summary:    audit.Summary{Lockfiles: 1, Total: 22, Clean: 22},
		DurationMS: 1250,
	}
	if err := RenderAudit(o, "test", result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Audit results",
		"Verdict:",
		"CLEAN",
		"Target:",
		"google",
		"Files:",
		"Dependencies:",
		"Duration:",
		"1.2s",
		"22",
		"No known malicious packages",
		"22 dependencies checked from 1 file",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestNewAuditProgressFindingCards(t *testing.T) {
	var stdout, stderr bytes.Buffer
	o := Options{Writer: &stdout, ErrOut: &stderr, NoColor: true}
	p, _ := NewAuditProgress(o, false)
	p.OnFinding(audit.Finding{
		Ecosystem: "npm",
		Name:      "evil",
		Version:   "9.9.9",
		IDs:       []string{"MAL-2026-STREAM"},
		Summary:   "Malicious code in evil (npm)",
		Lockfile:  "/tmp/example-app/yarn.lock",
		Source:    "/tmp/example-app/yarn.lock",
	})

	out := stdout.String()
	if !strings.Contains(out, "[MAL-2026-STREAM]") {
		t.Fatalf("expected streamed card on stdout: %s", out)
	}
	if !strings.Contains(out, "Lockfile: /tmp/example-app/yarn.lock") {
		t.Fatalf("expected lockfile on streamed card: %s", out)
	}
	if strings.Contains(stderr.String(), "[MAL-2026-STREAM]") {
		t.Fatalf("findings should not go to stderr: %s", stderr.String())
	}
}
