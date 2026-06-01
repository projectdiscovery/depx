//go:build unix

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverLockfilesUnix(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := discoverLockfilesUnix(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || filepath.Base(got[0]) != "package-lock.json" {
		t.Fatalf("unexpected lockfiles: %+v", got)
	}
}

func TestDiscoverLockfilesUnixSkipsGoModCache(t *testing.T) {
	root := t.TempDir()
	modCache := filepath.Join(root, "go", "pkg", "mod", "github.com", "foo@v1.0.0")
	project := filepath.Join(root, "go", "src", "app")
	if err := os.MkdirAll(modCache, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modCache, "go.mod"), []byte("module github.com/foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	projectLock := filepath.Join(project, "go.mod")
	if err := os.WriteFile(projectLock, []byte("module example.com/app\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := discoverLockfilesUnix(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != projectLock {
		t.Fatalf("expected project lockfile only, got %v", got)
	}
}
