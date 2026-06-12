package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	bin := binPath(t)
	cacheDir := t.TempDir()
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("cache_dir: %s\nfeed:\n  cache_ttl: 1h\n", cacheDir)), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := mockSourceServer(t)
	sourceURL := srv.URL + "/export"
	t.Setenv("DEPX_SOURCE_URL", sourceURL)

	runWithStdin := func(stdin string, args ...string) (string, int) {
		base := []string{"--disable-update-check", "--silent", "--config", cfgPath}
		cmd := exec.Command(bin, append(base, args...)...)
		cmd.Env = append(os.Environ(),
			"DEPX_SOURCE_URL="+sourceURL,
			"NO_COLOR=1",
		)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		var stdout, stderr strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else {
				t.Fatalf("exec %v: %v", args, err)
			}
		}
		if stderr.Len() > 0 && code != 0 {
			return stderr.String() + stdout.String(), code
		}
		return stdout.String(), code
	}

	run := func(args ...string) (string, int) {
		return runWithStdin("", args...)
	}

	t.Run("default feed json", func(t *testing.T) {
		out, code := run("-j", "--limit", "2")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "feed")
		if !strings.Contains(out, "MAL-2026-TEST1") {
			t.Fatalf("missing feed entry: %s", out)
		}
	})

	t.Run("feed since and ecosystem", func(t *testing.T) {
		out, code := run("-j", "--since", "48h", "-e", "npm", "-n", "1")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "feed")
	})

	t.Run("feed refresh", func(t *testing.T) {
		out, code := run("-j", "-n", "1")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "feed")
	})

	t.Run("check clean", func(t *testing.T) {
		out, code := run("-j", "npm:lodash")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "check")
		if !strings.Contains(out, `"verdict": "clean"`) {
			t.Fatalf("expected clean: %s", out)
		}
	})

	t.Run("check nonexistent bare package", func(t *testing.T) {
		out, code := run("-j", "depx-nonexistent-package-xyz-999")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "check")
		if !strings.Contains(out, `"verdict": "not_found"`) {
			t.Fatalf("expected not_found: %s", out)
		}
	})

	t.Run("check malicious", func(t *testing.T) {
		out, code := run("-j", "npm:evil-pkg")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, `"verdict": "malicious"`) {
			t.Fatalf("expected malicious: %s", out)
		}
		if !strings.Contains(out, `"url": "https://osv.dev/vulnerability/MAL-2026-TEST1"`) {
			t.Fatalf("expected advisory url: %s", out)
		}
	})

	t.Run("check alias bare ref", func(t *testing.T) {
		out, code := run("-j", "check", "apkeep")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "check")
		if !strings.Contains(out, `"total": 1`) {
			t.Fatalf("expected single check result, got: %s", out)
		}
		if !strings.Contains(out, `"verdict": "malicious"`) {
			t.Fatalf("expected malicious: %s", out)
		}
		if strings.Contains(out, `"ref": "check"`) {
			t.Fatalf("check alias must not treat keyword as package ref: %s", out)
		}
	})

	t.Run("search apkeep", func(t *testing.T) {
		out, code := run("-j", "search", "apkeep")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "search")
		if !strings.Contains(out, `"shown"`) || !strings.Contains(out, "apkeep") {
			t.Fatalf("expected search hit: %s", out)
		}
	})

	t.Run("check cross ecosystem bare ref", func(t *testing.T) {
		out, code := run("-j", "apkeep")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, `"verdict": "malicious"`) {
			t.Fatalf("expected malicious: %s", out)
		}
		if !strings.Contains(out, `"matched_ecosystems"`) || !strings.Contains(out, "PyPI") {
			t.Fatalf("expected PyPI match: %s", out)
		}
		if !strings.Contains(out, `"url": "https://osv.dev/vulnerability/MAL-2026-3431"`) {
			t.Fatalf("expected advisory url: %s", out)
		}
		if !strings.Contains(out, "bad-packages.kam193.eu") {
			t.Fatalf("expected reference url: %s", out)
		}
	})

	t.Run("check single ecosystem with flag", func(t *testing.T) {
		out, code := run("-j", "-e", "npm", "apkeep")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, `"verdict": "clean"`) {
			t.Fatalf("expected npm-only clean: %s", out)
		}
	})

	t.Run("bare ref check", func(t *testing.T) {
		out, code := run("-j", "-e", "npm", "lodash")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "check")
	})

	t.Run("id lookup", func(t *testing.T) {
		out, code := run("-j", "id", "MAL-2026-TEST1")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "id")
		if !strings.Contains(out, "evil-pkg") {
			t.Fatalf("missing id payload: %s", out)
		}
	})

	t.Run("id raw", func(t *testing.T) {
		out, code := run("id", "MAL-2026-TEST1", "--raw")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "Malicious code") {
			t.Fatalf("unexpected raw output: %s", out)
		}
	})

	t.Run("audit sbom fixture", func(t *testing.T) {
		fixture := filepath.Join("..", "testdata", "fixtures", "clean-sbom", "bom.cdx.json")
		out, code := run("-j", "audit", fixture)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "audit")
		if !strings.Contains(out, `"type": "sbom"`) {
			t.Fatalf("expected sbom source in result: %s", out)
		}
		if !strings.Contains(out, `"total": 1`) {
			t.Fatalf("expected one dependency from sbom: %s", out)
		}
		if !strings.Contains(out, `"malicious": 0`) {
			t.Fatalf("expected clean sbom scan: %s", out)
		}
	})

	t.Run("audit fixture", func(t *testing.T) {
		fixture := filepath.Join("..", "testdata", "fixtures", "clean-project")
		out, code := run("-j", "audit", fixture)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "audit")
		if !strings.Contains(out, `"total": 1`) && !strings.Contains(out, `"total": 2`) {
			t.Fatalf("expected dependencies in audit: %s", out)
		}
		if !strings.Contains(out, `"malicious": 0`) {
			t.Fatalf("expected clean audit: %s", out)
		}
		if !strings.Contains(out, `"mode": "local"`) {
			t.Fatalf("expected local audit mode: %s", out)
		}
	})

	t.Run("version", func(t *testing.T) {
		base := []string{"--disable-update-check", "--silent", "--config", cfgPath}
		cmd := exec.Command(bin, append(base, "version", "--disable-update-check")...)
		cmd.Env = append(os.Environ(), "DEPX_SOURCE_URL="+sourceURL, "NO_COLOR=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("version failed: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "v0.1.0") {
			t.Fatalf("missing version: %s", out)
		}
	})

	t.Run("human feed no-color", func(t *testing.T) {
		out, code := run("--no-color", "-n", "1")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out, "Malicious package & supply-chain intelligence") ||
			!strings.Contains(out, "top ecosystems") {
			t.Fatalf("expected human feed dashboard: %s", out)
		}
		if strings.Contains(out, "indexed corpus") || strings.Contains(out, "sync pending") {
			t.Fatalf("dashboard should not expose cache internals: %s", out)
		}
	})

	t.Run("json feed", func(t *testing.T) {
		out, code := run("-j", "-n", "1")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "feed")
	})

	t.Run("check stdin single ref", func(t *testing.T) {
		out, code := runWithStdin("apkeep\n", "-j")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "check")
		if !strings.Contains(out, `"verdict": "malicious"`) {
			t.Fatalf("expected malicious: %s", out)
		}
	})

	t.Run("check stdin multiple refs", func(t *testing.T) {
		out, code := runWithStdin("apkeep\nnpm:lodash\n", "-j")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "check")
		if !strings.Contains(out, `"total": 2`) {
			t.Fatalf("expected batch total: %s", out)
		}
		if !strings.Contains(out, `"verdict": "malicious"`) || !strings.Contains(out, `"verdict": "clean"`) {
			t.Fatalf("expected mixed verdicts: %s", out)
		}
	})

	t.Run("usage error empty stdin", func(t *testing.T) {
		_, code := runWithStdin("\n\n", "-j")
		if code != 2 {
			t.Fatalf("expected exit 2, got %d", code)
		}
	})

	t.Run("stdin advisory id routes to lookup", func(t *testing.T) {
		out, code := runWithStdin("MAL-2026-3431\n", "-j")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "id")
		if !strings.Contains(out, "Malicious code in apkeep (PyPI)") {
			t.Fatalf("expected advisory lookup: %s", out)
		}
		if strings.Contains(out, `"verdict": "clean"`) {
			t.Fatalf("advisory ID must not be checked as package: %s", out)
		}
	})

	t.Run("positional advisory id routes to lookup", func(t *testing.T) {
		out, code := run("-j", "MAL-2026-3431")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "id")
		if !strings.Contains(out, `"id": "MAL-2026-3431"`) {
			t.Fatalf("expected id lookup: %s", out)
		}
	})

	t.Run("json error envelope", func(t *testing.T) {
		out, code := run("-j", "--since", "not-a-duration", "-n", "1")
		if code != 2 {
			t.Fatalf("exit %d: %s", code, out)
		}
		assertJSONCommand(t, out, "error")
		if !strings.Contains(out, `"code": 2`) {
			t.Fatalf("expected usage code in json error: %s", out)
		}
	})
}
