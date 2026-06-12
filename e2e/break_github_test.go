package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIGitHubBreakCases(t *testing.T) {
	bin := binPath(t)
	cacheDir := t.TempDir()
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("cache_dir: %s\nfeed:\n  cache_ttl: 1h\ntimeout: 5s\n", cacheDir)), 0o644); err != nil {
		t.Fatal(err)
	}

	srcSrv := mockSourceServer(t)
	ghSrv := mockGitHubBreakServer(t)

	run := func(args ...string) (stdout, stderr string, exit int) {
		t.Helper()
		base := []string{"--disable-update-check", "--silent", "--config", cfgPath}
		cmd := exec.Command(bin, append(base, args...)...)
		cmd.Env = append(withoutGitHubTokenEnv(os.Environ()),
			"DEPX_SOURCE_URL="+srcSrv.URL+"/export",
			"DEPX_GITHUB_API_URL="+ghSrv.URL,
			"NO_COLOR=1",
		)
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

	parseCases := []struct {
		name       string
		args       []string
		wantExit   int
		wantSubstr string
	}{
		{"no args without token", []string{"github"}, 2, "set DEPX_GITHUB_TOKEN"},
		{"empty target", []string{"github", ""}, 2, "github target is required"},
		{"invalid chars", []string{"github", "!!!invalid!!!"}, 2, "invalid github target"},
		{"non github url", []string{"github", "https://example.com/acme/repo"}, 2, "invalid github target"},
		{"bare github url", []string{"github", "https://github.com/"}, 2, "invalid github target"},
		{"path traversal", []string{"github", "../../../etc/passwd"}, 2, "invalid github target"},
		{"shell metachars", []string{"github", "$(rm -rf /)"}, 2, "invalid github target"},
		{"oversized target", []string{"github", strings.Repeat("a", 4096)}, 2, "invalid github target"},
		{"negative limit", []string{"github", "-n", "-1", "breakorg"}, 2, "--limit must be >= 0"},
		{"excessive limit", []string{"github", "-n", "999999999", "breakorg"}, 2, "--limit exceeds maximum"},
		{"double subcommand", []string{"github", "github", "breakorg/good"}, 2, ""},
	}

	for _, tc := range parseCases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, exit := run(tc.args...)
			t.Logf("exit=%d stdout=%q stderr=%q", exit, trimForLog(stdout), trimForLog(stderr))
			if exit != tc.wantExit {
				t.Fatalf("expected exit %d, got %d stderr=%q", tc.wantExit, exit, stderr)
			}
			if tc.wantSubstr != "" && !strings.Contains(stderr+stdout, tc.wantSubstr) {
				t.Fatalf("expected output containing %q, got stderr=%q stdout=%q", tc.wantSubstr, stderr, stdout)
			}
		})
	}

	apiCases := []struct {
		name string
		args []string
	}{
		{"single repo sbom", []string{"github", "-j", "breakorg/good"}},
		{"org url", []string{"github", "-j", "https://github.com/breakorg"}},
		{"org bare name", []string{"github", "-j", "-n", "5", "breakorg"}},
		{"repo url git suffix", []string{"github", "-j", "https://github.com/breakorg/good.git"}},
		{"repo with garbage sbom skipped", []string{"github", "-j", "-n", "10", "breakorg"}},
		{"multiple targets mixed", []string{"github", "-j", "breakorg/good", "breakorg/missing", "!!!bad!!!"}},
		{"lockfile fallback", []string{"github", "-j", "breakorg/gomod"}},
		{"empty org", []string{"github", "-j", "emptyorg"}},
		{"unknown org", []string{"github", "-j", "missingorg"}},
		{"malformed sbom json", []string{"github", "-j", "breakorg/garbage"}},
		{"empty sbom packages", []string{"github", "-j", "breakorg/empty-sbom"}},
		{"sbom async timeout path", []string{"github", "-j", "breakorg/async"}},
		{"contents not json", []string{"github", "-j", "breakorg/bad-contents"}},
		{"unicode org name rejected", []string{"github", "пакет"}},
	}

	for _, tc := range apiCases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, exit := run(tc.args...)
			t.Logf("exit=%d stdout=%q stderr=%q", exit, trimForLog(stdout), trimForLog(stderr))
			if tc.name == "multiple targets mixed" {
				if exit != 2 {
					t.Fatalf("expected usage exit 2 for invalid mixed target, got %d", exit)
				}
				return
			}
			if tc.name == "unicode org name rejected" {
				if exit != 2 {
					t.Fatalf("expected usage exit 2, got %d", exit)
				}
				return
			}
			if tc.name == "unknown org" || tc.name == "empty org" {
				if exit != 2 && exit != 3 {
					t.Fatalf("expected error exit, got %d stderr=%q", exit, stderr)
				}
				return
			}
			if exit != 0 && exit != 3 {
				t.Fatalf("unexpected exit %d stderr=%q stdout=%q", exit, stderr, stdout)
			}
		})
	}

	t.Run("no args with token uses accessible repos", func(t *testing.T) {
		base := []string{"--disable-update-check", "--silent", "--config", cfgPath}
		cmd := exec.Command(bin, append(base, "github", "-j", "-n", "5")...)
		cmd.Env = append(withoutGitHubTokenEnv(os.Environ()),
			"DEPX_SOURCE_URL="+srcSrv.URL+"/export",
			"DEPX_GITHUB_API_URL="+ghSrv.URL,
			"GITHUB_TOKEN=test-token",
			"NO_COLOR=1",
		)
		var outBuf, errBuf strings.Builder
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				if ee.ExitCode() != 0 && ee.ExitCode() != 3 {
					t.Fatalf("exit %d stderr=%q stdout=%q", ee.ExitCode(), errBuf.String(), outBuf.String())
				}
			} else {
				t.Fatal(err)
			}
		}
		if !strings.Contains(outBuf.String(), `"command": "audit"`) {
			t.Fatalf("expected audit json, got stdout=%q stderr=%q", outBuf.String(), errBuf.String())
		}
	})

	t.Run("parallel github scans", func(t *testing.T) {
		errCh := make(chan error, 10)
		for i := 0; i < 10; i++ {
			go func() {
				_, _, exit := run("github", "-j", "breakorg/good")
				if exit != 0 && exit != 3 {
					errCh <- fmt.Errorf("exit %d", exit)
					return
				}
				errCh <- nil
			}()
		}
		for i := 0; i < 10; i++ {
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		}
	})
}
