package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverLockfilesSkipsNodeModules(t *testing.T) {
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

	got, err := discoverLockfiles(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || filepath.Base(got[0]) != "package-lock.json" {
		t.Fatalf("unexpected lockfiles: %+v", got)
	}
}

func TestResolveAuditTargetsLockfile(t *testing.T) {
	root := t.TempDir()
	lock := filepath.Join(root, "go.mod")
	if err := os.WriteFile(lock, []byte("module example.com/test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	targets, err := resolveAuditTargets([]string{lock})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || len(targets[0].pathsToExtract) != 1 || targets[0].pathsToExtract[0] != lock {
		t.Fatalf("unexpected targets: %+v", targets)
	}
}

func TestDiscoverLockfilesHomeNoDuplicateAudit(t *testing.T) {
	home := t.TempDir()
	githubDir := filepath.Join(home, "GitHub")
	project := filepath.Join(githubDir, "app")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(project, "go.mod")
	if err := os.WriteFile(lock, []byte("module example.com/app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "go.mod"), []byte("module example.com/home\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := discoverLockfilesHome(home, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 unique lockfiles, got %d: %v", len(got), got)
	}
}

func TestDiscoverLockfilesHomeSkipsGoModCache(t *testing.T) {
	home := t.TempDir()
	modCache := filepath.Join(home, "go", "pkg", "mod", "github.com", "foo@v1.0.0")
	project := filepath.Join(home, "go", "src", "app")
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

	got, err := discoverLockfilesHome(home, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != projectLock {
		t.Fatalf("expected only GOPATH project lockfile, got %v", got)
	}
}
