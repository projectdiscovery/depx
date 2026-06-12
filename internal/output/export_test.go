package output

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/audit"
)

func TestParseExportFormats(t *testing.T) {
	t.Run("empty defaults json", func(t *testing.T) {
		got, err := ParseExportFormats("")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != ExportJSON {
			t.Fatalf("got %v, want [json]", got)
		}
	})

	t.Run("multiple deduped", func(t *testing.T) {
		got, err := ParseExportFormats("csv, json, csv")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != ExportCSV || got[1] != ExportJSON {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("unknown rejected", func(t *testing.T) {
		if _, err := ParseExportFormats("yaml"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestResolveExportPath(t *testing.T) {
	t.Run("single json with explicit extension", func(t *testing.T) {
		got, err := ResolveExportPath("/tmp/result.json", ExportJSON, []ExportFormat{ExportJSON})
		if err != nil || got != "/tmp/result.json" {
			t.Fatalf("got %q err=%v", got, err)
		}
	})

	t.Run("single json without extension", func(t *testing.T) {
		got, err := ResolveExportPath("/tmp/result", ExportJSON, []ExportFormat{ExportJSON})
		if err != nil || got != "/tmp/result.json" {
			t.Fatalf("got %q err=%v", got, err)
		}
	})

	t.Run("multiple formats use basename", func(t *testing.T) {
		got, err := ResolveExportPath("/tmp/out.json", ExportCSV, []ExportFormat{ExportJSON, ExportCSV})
		if err != nil || got != "/tmp/out.csv" {
			t.Fatalf("got %q err=%v", got, err)
		}
	})

	t.Run("temp file", func(t *testing.T) {
		got, err := ResolveExportPath("", ExportCSV, []ExportFormat{ExportCSV})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Remove(got) }()
		if !strings.HasSuffix(got, ".csv") {
			t.Fatalf("expected .csv temp, got %q", got)
		}
	})
}

func TestWriteAuditCSV(t *testing.T) {
	t.Run("findings", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "findings.csv")
		published := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		result := &audit.Result{
			Findings: []audit.Finding{
				{
					Verdict:   "malicious",
					Ecosystem: "npm",
					Name:      "evil-pkg",
					Version:   "1.0.0",
					IDs:       []string{"MAL-1", "MAL-2"},
					Summary:   "bad package",
					Published: published,
					Lockfile:  "package-lock.json",
				},
			},
		}
		if err := WriteAuditCSV(path, result); err != nil {
			t.Fatal(err)
		}
		rows := readCSVRows(t, path)
		if len(rows) != 2 {
			t.Fatalf("rows = %d, want header + 1 finding", len(rows))
		}
		if rows[0][0] != "verdict" || rows[1][0] != "malicious" {
			t.Fatalf("unexpected csv: %#v", rows)
		}
		if rows[1][4] != "MAL-1;MAL-2" {
			t.Fatalf("ids column = %q", rows[1][4])
		}
	})

	t.Run("clean audit writes summary row", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "clean.csv")
		result := &audit.Result{
			Paths:      []string{"/Users/geekboy"},
			DurationMS: 8100,
			Summary: audit.Summary{
				Lockfiles:           1057,
				Total:               24379,
				SkippedPlaceholders: 2,
			},
		}
		if err := WriteAuditCSV(path, result); err != nil {
			t.Fatal(err)
		}
		rows := readCSVRows(t, path)
		if len(rows) != 2 {
			t.Fatalf("rows = %d, want header + summary", len(rows))
		}
		if rows[1][0] != "clean" {
			t.Fatalf("verdict = %q, want clean", rows[1][0])
		}
		if !strings.Contains(rows[1][5], "24379 dependencies checked from 1057 files") {
			t.Fatalf("summary = %q", rows[1][5])
		}
		if rows[1][11] != "/Users/geekboy" {
			t.Fatalf("project_dir = %q", rows[1][11])
		}
	})
}

func readCSVRows(t *testing.T, path string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := csv.NewReader(strings.NewReader(string(raw)))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestWriteAuditTextFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.txt")
	result := &audit.Result{
		Summary: audit.Summary{Total: 1, Lockfiles: 1},
	}
	if err := WriteAuditTextFile(path, result); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, "Audit results") {
		t.Fatalf("missing audit header: %q", body)
	}
	if strings.Contains(body, "\x1b[") {
		t.Fatalf("text export must not contain ANSI escapes")
	}
}
