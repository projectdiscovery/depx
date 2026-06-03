package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrichFinding(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	f := enrichFinding(Finding{
		Ecosystem: "npm",
		Name:      "evil-pkg",
		Lockfile:  lockfile,
	})

	projectDir, err := filepath.Abs(filepath.Dir(lockfile))
	if err != nil {
		t.Fatal(err)
	}
	if f.ProjectDir != projectDir {
		t.Fatalf("ProjectDir = %q, want %q", f.ProjectDir, projectDir)
	}
	if !strings.HasPrefix(f.ProjectURL, "file://") || !strings.Contains(f.ProjectURL, filepath.ToSlash(projectDir)) {
		t.Fatalf("ProjectURL = %q", f.ProjectURL)
	}
	if f.PackageURL != "https://www.npmjs.com/package/evil-pkg" {
		t.Fatalf("PackageURL = %q", f.PackageURL)
	}
}
