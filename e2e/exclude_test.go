package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2EAuditExcludePkg verifies that --exclude-pkg silently drops matched
// packages from findings. The mock OSV server flags evil-pkg as MAL-2026-TEST1.
func TestE2EAuditExcludePkg(t *testing.T) {
	osvSrv := mockOSVServer(t)
	osvURL := osvSrv.URL + "/v1"
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath, osvOutputEnv(osvURL)...)

	malLockfile := writeMaliciousLockfile(t)

	writeExclude := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "exclude.txt")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("baseline flags malicious package", func(t *testing.T) {
		out, code := r.run("-j", "audit", malLockfile)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "MAL-2026-TEST1") {
			t.Fatalf("expected malicious finding without exclude:\n%s", out)
		}
	})

	t.Run("exact entry suppresses finding", func(t *testing.T) {
		excl := writeExclude(t, "# false positive\nnpm:evil-pkg\n")
		out, code := r.run("-j", "audit", malLockfile, "--exclude-pkg", excl)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if strings.Contains(out, "MAL-2026-TEST1") {
			t.Fatalf("excluded package still reported:\n%s", out)
		}
	})

	t.Run("wildcard ecosystem suppresses finding", func(t *testing.T) {
		excl := writeExclude(t, "*:evil-pkg\n")
		out, code := r.run("-j", "audit", malLockfile, "--exclude-pkg", excl)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if strings.Contains(out, "MAL-2026-TEST1") {
			t.Fatalf("wildcard exclude did not suppress finding:\n%s", out)
		}
	})

	t.Run("non-matching entry keeps finding", func(t *testing.T) {
		excl := writeExclude(t, "npm:some-other-pkg\n")
		out, code := r.run("-j", "audit", malLockfile, "--exclude-pkg", excl)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "MAL-2026-TEST1") {
			t.Fatalf("non-matching exclude should not suppress finding:\n%s", out)
		}
	})

	t.Run("require-clean passes once excluded", func(t *testing.T) {
		excl := writeExclude(t, "npm:evil-pkg\n")
		out, code := r.run("audit", malLockfile, "--exclude-pkg", excl, "--require-clean")
		if code != 0 {
			t.Fatalf("require-clean should pass when only finding is excluded, exit %d:\n%s", code, out)
		}
	})

	t.Run("malformed exclude file errors", func(t *testing.T) {
		excl := writeExclude(t, "not-a-valid-line\n")
		out, code := r.run("audit", malLockfile, "--exclude-pkg", excl)
		if code == 0 {
			t.Fatalf("expected non-zero exit for malformed exclude file:\n%s", out)
		}
	})
}
