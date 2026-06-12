//go:build unix

package audit

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/projectdiscovery/depx/internal/lockfile"
)

// discoverLockfilesUnix finds only whitelisted lockfile names using find(1) with -prune.
// It never descends into node_modules, .git, etc.
func discoverLockfilesUnix(root string) ([]string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	pruneNames := []string{
		"node_modules", ".git", ".hg", ".svn", ".next", ".turbo", ".cache",
		".pnpm-store", ".venv", "venv", "vendor", "dist", "build", "out",
		"target", "__pycache__", "coverage", "tmp", "temp", ".idea", ".vscode",
	}
	pathPrunes := []string{
		"*/go/pkg/mod",
		"*/go/pkg/sumdb",
	}
	lockNames := append([]string(nil), lockfile.RootNames...)
	sort.Strings(lockNames)

	args := []string{root, "("}
	first := true
	for _, pattern := range pathPrunes {
		if !first {
			args = append(args, "-o")
		}
		args = append(args, "-path", pattern)
		first = false
	}
	for _, n := range pruneNames {
		if !first {
			args = append(args, "-o")
		}
		args = append(args, "-name", n)
		first = false
	}
	args = append(args, ")", "-prune", "-o", "(")
	for i, name := range lockNames {
		if i > 0 {
			args = append(args, "-o")
		}
		args = append(args, "-name", name)
	}
	args = append(args, ")", "-print")

	cmd := exec.Command("find", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("find: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("find: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	found := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := os.Stat(line); err != nil {
			continue
		}
		found = append(found, line)
	}
	sort.Strings(found)
	return found, nil
}
