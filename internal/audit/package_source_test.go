package audit

import (
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func TestPackageToDependencyUsesAbsoluteLockfilePath(t *testing.T) {
	lockfile := filepath.Join(t.TempDir(), "package-lock.json")
	pkg := &extractor.Package{
		Name:      "evil",
		Version:   "1.0.0",
		Locations: []string{"package-lock.json"},
	}

	dep := packageToDependency(pkg, lockfile, SourceTypeLockfile, "")
	want, err := filepath.Abs(lockfile)
	if err != nil {
		t.Fatal(err)
	}
	if dep.Source != want {
		t.Fatalf("Source = %q, want absolute lockfile path %q", dep.Source, want)
	}
}
