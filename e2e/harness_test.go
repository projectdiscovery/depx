package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var sharedBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "depx-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}
	bin := filepath.Join(dir, "depx")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/depx")
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	sharedBin = bin
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func binPath(t *testing.T) string {
	t.Helper()
	if sharedBin == "" {
		t.Fatal("e2e binary not built")
	}
	return sharedBin
}

func writeTestConfig(t *testing.T, cacheDir string, extraYAML string) string {
	t.Helper()
	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "config.yaml")
	body := fmt.Sprintf("cache_dir: %s\nfeed:\n  cache_ttl: 1h\ntimeout: 30s\n", cacheDir)
	if extraYAML != "" {
		body += extraYAML
	}
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func trimForLog(s string) string {
	s = strings.ReplaceAll(s, "\n", `\n`)
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

type e2eRunner struct {
	t       *testing.T
	bin     string
	cfgPath string
	env     []string
}

func newE2ERunner(t *testing.T, cfgPath string, extraEnv ...string) *e2eRunner {
	t.Helper()
	return &e2eRunner{
		t:       t,
		bin:     binPath(t),
		cfgPath: cfgPath,
		env:     append(append([]string(nil), extraEnv...), "NO_COLOR=1"),
	}
}

func (r *e2eRunner) run(args ...string) (stdout string, exit int) {
	return r.runWithStdin("", args...)
}

func (r *e2eRunner) runWithStdin(stdin string, args ...string) (stdout string, exit int) {
	r.t.Helper()
	base := []string{"--disable-update-check", "--silent", "--config", r.cfgPath}
	cmd := exec.Command(r.bin, append(base, args...)...)
	cmd.Env = append(os.Environ(), r.env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	} else {
		cmd.Stdin = devNullStdin(r.t)
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
			r.t.Fatalf("exec %v: %v", args, err)
		}
	}
	combined := outBuf.String() + errBuf.String()
	if strings.Contains(combined, "panic:") || strings.Contains(combined, "runtime error:") {
		r.t.Fatalf("panic in %v: %s", args, combined)
	}
	if errBuf.Len() > 0 && exit != 0 {
		return combined, exit
	}
	return outBuf.String(), exit
}

func devNullStdin(t *testing.T) *os.File {
	t.Helper()
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func withoutEmbeddedSeedEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			out = append(out, kv)
			continue
		}
		if key == "DEPX_DISABLE_EMBEDDED_SEED" {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "DEPX_DISABLE_EMBEDDED_SEED=1")
}

func withoutGitHubTokenEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		key, _, ok := strings.Cut(kv, "=")
		if !ok {
			out = append(out, kv)
			continue
		}
		switch key {
		case "DEPX_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN":
			continue
		}
		out = append(out, kv)
	}
	return out
}
