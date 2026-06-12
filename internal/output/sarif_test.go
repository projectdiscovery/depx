package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/depx/internal/audit"
)

func TestWriteSARIF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "report.sarif")

	result := &audit.Result{
		Findings: []audit.Finding{
			{
				Verdict:   "malicious",
				Ecosystem: "npm",
				Name:      "left-pad",
				Version:   "1.3.0",
				IDs:       []string{"MAL-2026-1"},
				Summary:   "malicious install script",
				Lockfile:  "app/package-lock.json",
			},
			{
				Verdict:   "suspicious",
				Ecosystem: "pypi",
				Name:      "evil",
				Version:   "0.0.1",
				Source:    "reqs.txt",
			},
		},
	}

	written, err := WriteSARIF(path, "v1.2.3", result)
	if err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if written != path {
		t.Fatalf("written path = %q, want %q", written, path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	var doc sarifLog
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("sarif is not valid json: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "depx" || run.Tool.Driver.Version != "v1.2.3" {
		t.Fatalf("unexpected driver: %+v", run.Tool.Driver)
	}
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Fatalf("malicious finding level = %q, want error", run.Results[0].Level)
	}
	if run.Results[1].Level != "warning" {
		t.Fatalf("suspicious finding level = %q, want warning", run.Results[1].Level)
	}
	if run.Results[0].RuleID != "MAL-2026-1" {
		t.Fatalf("ruleId = %q, want MAL-2026-1", run.Results[0].RuleID)
	}
	if len(run.Results[0].Locations) != 1 ||
		run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "app/package-lock.json" {
		t.Fatalf("unexpected location: %+v", run.Results[0].Locations)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 unique rules, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestWriteSARIFDedupesRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.sarif")
	result := &audit.Result{
		Findings: []audit.Finding{
			{Verdict: "malicious", Name: "a", IDs: []string{"MAL-1"}},
			{Verdict: "malicious", Name: "b", IDs: []string{"MAL-1"}},
		},
	}
	if _, err := WriteSARIF(path, "v1", result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	raw, _ := os.ReadFile(path)
	var doc sarifLog
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected rules deduped to 1, got %d", len(doc.Runs[0].Tool.Driver.Rules))
	}
	if len(doc.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(doc.Runs[0].Results))
	}
}

func TestWriteResultFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out", "result.json")
	result := &audit.Result{Dependencies: 7}

	written, err := WriteResultFile(path, "v9", "audit", result)
	if err != nil {
		t.Fatalf("WriteResultFile: %v", err)
	}
	if written != path {
		t.Fatalf("path = %q, want %q", written, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("result file is not a valid envelope: %v", err)
	}
	if env.Command != "audit" || env.DepxVersion != "v9" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
}
