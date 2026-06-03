package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIBreakCases(t *testing.T) {
	bin := binPath(t)
	cacheDir := t.TempDir()
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("cache_dir: %s\nfeed:\n  cache_ttl: 1h\ntimeout: 30s\n", cacheDir)), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := mockOSVServer(t)
	osvURL := srv.URL + "/v1"

	run := func(stdin string, args ...string) (stdout string, stderr string, exit int) {
		t.Helper()
		base := []string{"--disable-update-check", "--silent", "--config", cfgPath}
		cmd := exec.Command(bin, append(base, args...)...)
		cmd.Env = append(os.Environ(),
			"DEPX_OSV_URL="+osvURL,
			"DEPX_MODIFIED_INDEX_URL="+srv.URL+"/modified_id.csv",
			"NO_COLOR=1",
		)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		var outBuf, errBuf strings.Builder
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		err := cmd.Run()
		exit = 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				exit = ee.ExitCode()
			} else {
				t.Fatalf("exec failed: %v", err)
			}
		}
		combined := outBuf.String() + errBuf.String()
		if strings.Contains(combined, "panic:") || strings.Contains(combined, "runtime error:") {
			t.Fatalf("panic in %v: %s", args, combined)
		}
		return outBuf.String(), errBuf.String(), exit
	}

	cases := []struct {
		name string
		in   string
		args []string
	}{
		{"empty stdin check", "", nil},
		{"blank lines only", "\n\n  \n# comment\n", []string{"-j"}},
		{"null byte ref", "foo\x00bar\n", []string{"-j"}},
		{"unicode ref", "пакет\n", []string{"-j"}},
		{"oversized ref", strings.Repeat("a", 256*1024) + "\n", []string{"-j"}},
		{"shell metachars", "$(rm -rf /)\n; DROP TABLE;\n", []string{"-j"}},
		{"fake mal id", "MAL-9999-999999\n", []string{"-j"}},
		{"ghsa malformed", "GHSA-not-valid\n", []string{"-j"}},
		{"mix package and id", "lodash\nMAL-2026-3431\n", []string{"-j"}},
		{"invalid since", "", []string{"--since", "not-a-duration", "-n", "1", "-j"}},
		{"negative limit", "", []string{"-n", "-1", "-j"}},
		{"excessive limit", "", []string{"-n", "999999999", "-j"}},
		{"npm empty name", "npm:\n", []string{"-j"}},
		{"malformed purl", "pkg:noslash\n", []string{"-j"}},
		{"multiple at", "npm:foo@bar@baz\n", []string{"-j"}},
		{"id empty", "", []string{"id", ""}},
		{"id spaces", "", []string{"id", "MAL 2026 3431"}},
		{"id traversal", "", []string{"id", "../../../etc/passwd"}},
		{"audit dev null", "", []string{"audit", "/dev/null", "-j"}},
		{"audit missing path", "", []string{"audit", "/no/such/depx-break-path", "-j"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, exit := run(tc.in, tc.args...)
			t.Logf("exit=%d stdout=%q stderr=%q", exit, trimForLog(stdout), trimForLog(stderr))
			switch tc.name {
			case "negative limit", "excessive limit":
				if exit != 2 {
					t.Fatalf("expected usage exit 2, got %d stderr=%q", exit, stderr)
				}
			case "oversized ref":
				if exit != 2 {
					t.Fatalf("expected usage exit 2, got %d stdout=%q", exit, trimForLog(stdout))
				}
				if !strings.Contains(stdout, "stdin line exceeds maximum size") {
					t.Fatalf("expected friendly oversized stdin error, exit=%d stdout=%q", exit, trimForLog(stdout))
				}
			case "npm empty name":
				if exit != 2 {
					t.Fatalf("expected usage exit 2, got %d stdout=%q", exit, trimForLog(stdout))
				}
				if !strings.Contains(stdout, "package name is required") {
					t.Fatalf("expected npm empty name usage error, exit=%d stdout=%q", exit, trimForLog(stdout))
				}
			}
		})
	}

	t.Run("garbage sbom file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.cdx.json")
		if err := os.WriteFile(path, []byte("{not-json"), 0o644); err != nil {
			t.Fatal(err)
		}
		run("", "audit", path, "-j")
	})

	t.Run("batch 200 refs", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 200; i++ {
			b.WriteString("lodash\n")
		}
		stdout, _, exit := run(b.String(), "-j")
		if exit != 0 {
			t.Fatalf("batch exit %d: %s", exit, trimForLog(stdout))
		}
		if !strings.Contains(stdout, `"total": 200`) {
			t.Fatalf("expected 200 results: %s", trimForLog(stdout))
		}
	})

	t.Run("parallel checks same cache", func(t *testing.T) {
		errCh := make(chan error, 20)
		for i := 0; i < 20; i++ {
			go func() {
				_, _, exit := run("lodash\n", "-j")
				if exit != 0 {
					errCh <- fmt.Errorf("exit %d", exit)
					return
				}
				errCh <- nil
			}()
		}
		for i := 0; i < 20; i++ {
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		}
	})
}
