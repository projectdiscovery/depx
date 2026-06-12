package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMaliciousLockfile writes an npm lockfile containing evil-pkg, which the
// mock inventory flags as malicious (MAL-2026-TEST1).
func writeMaliciousLockfile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := `{
  "name": "mal-fixture",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "mal-fixture" },
    "node_modules/evil-pkg": { "version": "1.0.0" }
  }
}`
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func extractNoticePath(t *testing.T, out, label string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, label); i >= 0 {
			return strings.TrimSpace(line[i+len(label):])
		}
	}
	t.Fatalf("notice %q not found in output:\n%s", label, out)
	return ""
}

func assertResultFile(t *testing.T, path, command string) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatalf("expected absolute path in notice, got %q", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result file %q: %v", path, err)
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		Command       string `json:"command"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("result file %q is not valid json: %v", path, err)
	}
	if env.SchemaVersion != "1" || env.Command != command {
		t.Fatalf("result file envelope = {schema:%q command:%q}, want {1 %q}", env.SchemaVersion, env.Command, command)
	}
}

func TestE2EAuditOutputOptions(t *testing.T) {
	srcSrv := mockSourceServer(t)
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath, sourceEnv(srcSrv)...)

	cleanProject := filepath.Join("..", "testdata", "fixtures", "clean-project")
	malLockfile := writeMaliciousLockfile(t)

	// Default text mode: a JSON result file is written to a temp location and
	// its absolute path is reported on stdout.
	t.Run("default writes temp json with absolute path", func(t *testing.T) {
		out, code := r.run("audit", cleanProject)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "JSON result:") {
			t.Fatalf("expected JSON result notice, got:\n%s", out)
		}
		path := extractNoticePath(t, out, "JSON result:")
		defer func() { _ = os.Remove(path) }()
		assertResultFile(t, path, "audit")
	})

	// --output/-o redirects the JSON result to a chosen path instead of temp.
	t.Run("output flag redirects json", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "out", "result.json")
		out, code := r.run("audit", cleanProject, "-o", dest)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		notice := extractNoticePath(t, out, "JSON result:")
		if notice != dest {
			t.Fatalf("notice path = %q, want %q", notice, dest)
		}
		assertResultFile(t, dest, "audit")
	})

	// --sarif-export writes a SARIF report; with a malicious dependency it must
	// contain an error-level result. The default temp JSON is still written
	// (options are independent).
	t.Run("sarif export with findings", func(t *testing.T) {
		sarifPath := filepath.Join(t.TempDir(), "report.sarif")
		out, code := r.run("audit", malLockfile, "--sarif-export", sarifPath)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "SARIF report:") || !strings.Contains(out, "JSON result:") {
			t.Fatalf("expected both SARIF and JSON notices, got:\n%s", out)
		}
		if extractNoticePath(t, out, "SARIF report:") != sarifPath {
			t.Fatalf("sarif notice path mismatch:\n%s", out)
		}

		raw, err := os.ReadFile(sarifPath)
		if err != nil {
			t.Fatalf("read sarif: %v", err)
		}
		var doc struct {
			Version string `json:"version"`
			Runs    []struct {
				Tool struct {
					Driver struct {
						Name string `json:"name"`
					} `json:"driver"`
				} `json:"tool"`
				Results []struct {
					RuleID string `json:"ruleId"`
					Level  string `json:"level"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("sarif not valid json: %v\n%s", err, raw)
		}
		if doc.Version != "2.1.0" {
			t.Fatalf("sarif version = %q, want 2.1.0", doc.Version)
		}
		if len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "depx" {
			t.Fatalf("unexpected sarif run/tool: %+v", doc.Runs)
		}
		if len(doc.Runs[0].Results) == 0 {
			t.Fatalf("expected at least one SARIF result for malicious dependency:\n%s", raw)
		}
		if doc.Runs[0].Results[0].Level != "error" {
			t.Fatalf("malicious result level = %q, want error", doc.Runs[0].Results[0].Level)
		}
	})

	// --json mode: stdout stays a valid JSON envelope; -o still writes the file.
	t.Run("json mode with output flag", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "j.json")
		out, code := r.run("-j", "audit", cleanProject, "-o", dest)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "audit")
		assertResultFile(t, dest, "audit")
	})

	// --json mode without -o: stdout is pure JSON (path notice, if any, goes to
	// stderr and never corrupts stdout).
	t.Run("json mode stdout stays clean", func(t *testing.T) {
		out, code := r.run("-j", "audit", cleanProject)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "audit")
		if strings.Contains(out, "JSON result:") {
			t.Fatalf("path notice leaked into --json stdout:\n%s", out)
		}
	})

	// --output-format csv writes a flat findings table.
	t.Run("output format csv", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "result.csv")
		out, code := r.run("audit", malLockfile, "--output-format", "csv", "-o", dest)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "CSV result:") {
			t.Fatalf("expected CSV notice, got:\n%s", out)
		}
		if strings.Contains(out, "JSON result:") {
			t.Fatalf("csv-only export should not write json:\n%s", out)
		}
		raw, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "verdict,ecosystem") {
			t.Fatalf("unexpected csv header: %s", raw)
		}
		if !strings.Contains(string(raw), "malicious") {
			t.Fatalf("expected malicious finding row in csv: %s", raw)
		}
	})

	// Clean audits still produce a useful CSV summary row.
	t.Run("output format csv clean audit", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "clean.csv")
		out, code := r.run("audit", cleanProject, "--output-format", "csv", "-o", dest)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		raw, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		if !strings.Contains(body, "clean") {
			t.Fatalf("expected clean summary row in csv: %s", body)
		}
		if !strings.Contains(body, "dependencies checked") {
			t.Fatalf("expected dependency stats in csv summary: %s", body)
		}
	})

	// Multiple formats write separate files from one basename.
	t.Run("multiple output formats", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "multi")
		out, code := r.run("audit", cleanProject, "--output-format", "json,csv,txt", "-o", base)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		for _, label := range []string{"JSON result:", "CSV result:", "Text result:"} {
			if !strings.Contains(out, label) {
				t.Fatalf("missing %s in output:\n%s", label, out)
			}
		}
		jsonPath := base + ".json"
		csvPath := base + ".csv"
		txtPath := base + ".txt"
		assertResultFile(t, jsonPath, "audit")
		if raw, err := os.ReadFile(csvPath); err != nil || !strings.Contains(string(raw), "verdict") {
			t.Fatalf("csv file missing or invalid: err=%v raw=%q", err, raw)
		}
		if raw, err := os.ReadFile(txtPath); err != nil || !strings.Contains(string(raw), "Audit results") {
			t.Fatalf("txt file missing or invalid: err=%v raw=%q", err, raw)
		}
	})

	// Independence: -o and --sarif-export together both produce files.
	t.Run("output and sarif together", func(t *testing.T) {
		jsonDest := filepath.Join(t.TempDir(), "both.json")
		sarifDest := filepath.Join(t.TempDir(), "both.sarif")
		out, code := r.run("audit", malLockfile, "-o", jsonDest, "--sarif-export", sarifDest)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertResultFile(t, jsonDest, "audit")
		if _, err := os.Stat(sarifDest); err != nil {
			t.Fatalf("sarif file not written: %v", err)
		}
	})
}
