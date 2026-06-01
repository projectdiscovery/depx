package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

type intelFixture struct {
	name         string
	env          func(osvURL, pdURL string) []string
	feedMarker   string
	maliciousID  string
	advisoryID   string
	apkeepID     string
}

func intelFixtures() []intelFixture {
	return []intelFixture{
		{
			name: "osv",
			env: func(osvURL, _ string) []string {
				return withoutEmbeddedSeedEnv([]string{
					"DEPX_INTEL_SOURCE=osv",
					"DEPX_OSV_URL=" + osvURL,
					"DEPX_MODIFIED_INDEX_URL=" + strings.TrimSuffix(osvURL, "/v1") + "/modified_id.csv",
				})
			},
			feedMarker:  "MAL-2026-TEST1",
			maliciousID: "MAL-2026-TEST1",
			advisoryID:  "MAL-2026-TEST1",
			apkeepID:    "MAL-2026-3431",
		},
		{
			name: "pd",
			env: func(_, pdURL string) []string {
				return withoutEmbeddedSeedEnv([]string{
					"DEPX_INTEL_SOURCE=pd",
					"DEPX_PD_API_TOKEN=test-token",
					"DEPX_PD_API_URL=" + pdURL,
				})
			},
			feedMarker:  "evil-pkg",
			maliciousID: "GHSCAN-MAL-1",
			advisoryID:  "GHSCAN-MAL-1",
			apkeepID:    "GHSCAN-MAL-APKEEP",
		},
	}
}

func TestE2EIntelSources(t *testing.T) {
	osvSrv := mockOSVServer(t)
	pdSrv := mockPDServer(t)
	ghSrv := mockGitHubBreakServer(t)
	osvURL := osvSrv.URL + "/v1"

	cleanProject := filepath.Join("..", "testdata", "fixtures", "clean-project")
	cleanSBOM := filepath.Join("..", "testdata", "fixtures", "clean-sbom", "bom.cdx.json")

	for _, fx := range intelFixtures() {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			cfgPath := writeTestConfig(t, cacheDir, "")
			r := newE2ERunner(t, cfgPath, fx.env(osvURL, pdSrv.URL)...)

			t.Run("feed default json", func(t *testing.T) {
				out, code := r.run("-j", "-n", "2")
				if code != 0 {
					t.Fatalf("exit %d: %s", code, out)
				}
				assertJSONCommand(t, out, "feed")
				if !strings.Contains(out, fx.feedMarker) {
					t.Fatalf("missing feed marker %q: %s", fx.feedMarker, out)
				}
			})

			t.Run("feed since ecosystem limit", func(t *testing.T) {
				out, code := r.run("-j", "--since", "48h", "-e", "npm", "-n", "1")
				if code != 0 {
					t.Fatalf("exit %d: %s", code, out)
				}
				assertJSONCommand(t, out, "feed")
			})

			t.Run("feed refresh", func(t *testing.T) {
				out, code := r.run("-j", "-n", "1")
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
				if !strings.Contains(out, "Showing") {
					t.Fatalf("expected human feed output: %s", out)
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
				out, code := r.run("-j", "id", fx.advisoryID)
				if code != 0 {
					t.Fatalf("exit %d: %s", code, out)
				}
				assertJSONCommand(t, out, "id")
				if !strings.Contains(out, "evil-pkg") && !strings.Contains(out, "apkeep") {
					t.Fatalf("missing advisory payload: %s", out)
				}
			})

			t.Run("id raw", func(t *testing.T) {
				out, code := r.run("id", fx.advisoryID, "--raw")
				if code != 0 {
					t.Fatalf("exit %d: %s", code, out)
				}
				if !strings.Contains(out, "Malicious code") {
					t.Fatalf("expected raw summary: %s", out)
				}
			})

			t.Run("positional advisory id", func(t *testing.T) {
				out, code := r.run("-j", fx.apkeepID)
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

			t.Run("audit require-clean", func(t *testing.T) {
				out, code := r.run("-j", "audit", cleanProject, "--require-clean")
				if code != 0 {
					t.Fatalf("exit %d: %s", code, out)
				}
				if !strings.Contains(out, `"malicious": 0`) {
					t.Fatalf("expected clean require-clean audit: %s", out)
				}
			})

			t.Run("audit warm cache", func(t *testing.T) {
				out, code := r.run("-j", "audit", cleanProject)
				if code != 0 {
					t.Fatalf("exit %d: %s", code, out)
				}
				assertJSONCommand(t, out, "audit")
			})

			t.Run("github repo", func(t *testing.T) {
				gh := newE2ERunner(t, cfgPath, append(fx.env(osvURL, pdSrv.URL),
					"DEPX_GITHUB_API_URL="+ghSrv.URL,
				)...)
				gh.env = withoutGitHubTokenEnv(append(gh.env, "DEPX_GITHUB_API_URL="+ghSrv.URL))
				out, code := gh.run("-j", "github", "breakorg/good")
				if code != 0 && code != 3 {
					t.Fatalf("exit %d: %s", code, out)
				}
				if code == 0 {
					assertJSONCommand(t, out, "audit")
				}
			})

			t.Run("github org limit verbose", func(t *testing.T) {
				gh := newE2ERunner(t, cfgPath, append(fx.env(osvURL, pdSrv.URL),
					"DEPX_GITHUB_API_URL="+ghSrv.URL,
				)...)
				gh.env = withoutGitHubTokenEnv(append(gh.env, "DEPX_GITHUB_API_URL="+ghSrv.URL))
				_, code := gh.run("-v", "github", "-n", "2", "breakorg")
				if code != 0 && code != 3 {
					t.Fatalf("unexpected exit %d", code)
				}
			})

			t.Run("timeout flag", func(t *testing.T) {
				out, code := r.run("--timeout", "5s", "-j", "-n", "1")
				if code != 0 {
					t.Fatalf("exit %d: %s", code, out)
				}
				assertJSONCommand(t, out, "feed")
			})
		})
	}
}

func TestE2EPDFallsBackWithoutToken(t *testing.T) {
	osvSrv := mockOSVServer(t)
	cacheDir := t.TempDir()
	cfgPath := writeTestConfig(t, cacheDir, "")
	r := newE2ERunner(t, cfgPath, withoutEmbeddedSeedEnv([]string{
		"DEPX_INTEL_SOURCE=pd",
		"DEPX_OSV_URL=" + osvSrv.URL + "/v1",
		"DEPX_MODIFIED_INDEX_URL=" + osvSrv.URL + "/modified_id.csv",
	})...)
	out, code := r.run("-j", "-n", "1")
	if code != 0 {
		t.Fatalf("expected OSV fallback feed, got exit %d: %s", code, out)
	}
	if !strings.Contains(out, `"source": "osv"`) {
		t.Fatalf("expected OSV fallback when PD token missing: %s", out)
	}
}
