package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestE2EIntelSource exercises every command against the single inventory
// source served from the mock gzip export.
func TestE2EIntelSource(t *testing.T) {
	srcSrv := mockSourceServer(t)
	ghSrv := mockGitHubBreakServer(t)

	cleanProject := filepath.Join("..", "testdata", "fixtures", "clean-project")
	cleanSBOM := filepath.Join("..", "testdata", "fixtures", "clean-sbom", "bom.cdx.json")

	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath, sourceEnv(srcSrv)...)

	t.Run("feed default json", func(t *testing.T) {
		out, code := r.run("-j", "-n", "2")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "feed")
		if !strings.Contains(out, "MAL-2026-TEST1") {
			t.Fatalf("missing feed marker: %s", out)
		}
	})

	t.Run("feed since ecosystem limit", func(t *testing.T) {
		out, code := r.run("-j", "--since", "48h", "-e", "npm", "-n", "1")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "feed")
	})

	t.Run("feed human no-color", func(t *testing.T) {
		out, code := r.run("--no-color", "-n", "1")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "Malicious package & supply-chain intelligence") {
			t.Fatalf("expected human feed dashboard: %s", out)
		}
	})

	t.Run("check clean explicit", func(t *testing.T) {
		out, code := r.run("-j", "npm:lodash")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "check")
		if !strings.Contains(out, `"verdict": "clean"`) {
			t.Fatalf("expected clean: %s", out)
		}
	})

	t.Run("check malicious explicit", func(t *testing.T) {
		out, code := r.run("-j", "npm:evil-pkg")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "check")
		if !strings.Contains(out, `"verdict": "malicious"`) {
			t.Fatalf("expected malicious: %s", out)
		}
	})

	t.Run("check not found", func(t *testing.T) {
		out, code := r.run("-j", "depx-nonexistent-package-xyz-999")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, `"verdict": "not_found"`) {
			t.Fatalf("expected not_found: %s", out)
		}
	})

	t.Run("check bare cross ecosystem", func(t *testing.T) {
		out, code := r.run("-j", "apkeep")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, `"verdict": "malicious"`) {
			t.Fatalf("expected malicious: %s", out)
		}
	})

	t.Run("check ecosystem filter", func(t *testing.T) {
		out, code := r.run("-j", "-e", "npm", "apkeep")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, `"verdict": "clean"`) {
			t.Fatalf("expected npm-only clean: %s", out)
		}
	})

	t.Run("check stdin batch", func(t *testing.T) {
		out, code := r.runWithStdin("apkeep\nnpm:lodash\n", "-j")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "check")
		if !strings.Contains(out, `"total": 2`) {
			t.Fatalf("expected batch total: %s", out)
		}
	})

	t.Run("id lookup json", func(t *testing.T) {
		out, code := r.run("-j", "id", "MAL-2026-TEST1")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "id")
		if !strings.Contains(out, "evil-pkg") {
			t.Fatalf("missing advisory payload: %s", out)
		}
	})

	t.Run("id raw", func(t *testing.T) {
		out, code := r.run("id", "MAL-2026-3431", "--raw")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "Malicious code") {
			t.Fatalf("expected raw summary: %s", out)
		}
	})

	t.Run("positional advisory id", func(t *testing.T) {
		out, code := r.run("-j", "MAL-2026-3431")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "id")
		if !strings.Contains(out, "apkeep") {
			t.Fatalf("expected apkeep advisory: %s", out)
		}
	})

	t.Run("search by name", func(t *testing.T) {
		out, code := r.run("-j", "search", "apkeep")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "search")
		if !strings.Contains(out, "apkeep") {
			t.Fatalf("expected apkeep search hit: %s", out)
		}
	})

	t.Run("search ecosystem filter", func(t *testing.T) {
		out, code := r.run("-j", "search", "apkeep", "-e", "npm", "-n", "5")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "search")
		if strings.Contains(out, `"name": "apkeep"`) {
			t.Fatalf("expected npm filter to exclude PyPI apkeep: %s", out)
		}
	})

	t.Run("audit project", func(t *testing.T) {
		out, code := r.run("-j", "audit", cleanProject)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "audit")
		if !strings.Contains(out, `"malicious": 0`) {
			t.Fatalf("expected clean audit: %s", out)
		}
	})

	t.Run("audit sbom", func(t *testing.T) {
		out, code := r.run("-j", "audit", cleanSBOM)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "audit")
		if !strings.Contains(out, `"type": "sbom"`) {
			t.Fatalf("expected sbom source: %s", out)
		}
	})

	t.Run("github repo", func(t *testing.T) {
		gh := newE2ERunner(t, cfgPath, append(sourceEnv(srcSrv), "DEPX_GITHUB_API_URL="+ghSrv.URL)...)
		gh.env = withoutGitHubTokenEnv(append(gh.env, "DEPX_GITHUB_API_URL="+ghSrv.URL))
		out, code := gh.run("-j", "github", "breakorg/good")
		if code != 0 && code != 3 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if code == 0 {
			assertJSONCommand(t, out, "audit")
		}
	})
}
