package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAuditPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	got := defaultAuditPaths()
	if len(got) != 1 || got[0] != home {
		t.Fatalf("expected home default, got %+v", got)
	}
}

func TestShouldSkipDirPath(t *testing.T) {
	if !shouldSkipDirPath("/Users/x/go/pkg/mod/cache/download") {
		t.Fatal("expected go mod cache skip")
	}
	if !shouldSkipDirPath("/Users/x/go/pkg/mod/github.com/foo@v1.0.0") {
		t.Fatal("expected go module cache skip")
	}
	if shouldSkipDirPath("/Users/x/projects/example-app") {
		t.Fatal("did not expect project path skip")
	}
	if shouldSkipDirPath("/Users/x/go/src/example.com/app") {
		t.Fatal("did not expect GOPATH project path skip")
	}
}

func TestAuditNpmNodeModules(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "lodash")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"lodash","version":"4.17.21"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := auditNpmNodeModules(root)
	if len(deps) != 1 || deps[0].Name != "lodash" {
		t.Fatalf("unexpected deps: %+v", deps)
	}
}
