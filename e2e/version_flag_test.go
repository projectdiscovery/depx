package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestE2EVersionFlag(t *testing.T) {
	bin := binPath(t)

	for _, args := range [][]string{
		{"--version", "--disable-update-check"},
		{"-version", "--disable-update-check"},
		{"-V", "--disable-update-check"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := exec.Command(bin, args...)
			cmd.Env = append(os.Environ(), "NO_COLOR=1")
			var stdout, stderr strings.Builder
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("run failed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if !strings.Contains(combined, "Current version") {
				t.Fatalf("expected version output, got stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if strings.Contains(combined, "quick start") {
				t.Fatalf("-version/--version should not run default dashboard:\n%s", combined)
			}
		})
	}
}
