package audit

import (
	"context"
	"path/filepath"
	"testing"
)

func TestExtractFromSBOMFixture(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "clean-sbom", "bom.cdx.json")
	root := filepath.Dir(fixture)

	deps, err := extractFromSource(context.Background(), root, fixture, SourceTypeSBOM, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(deps))
	}
	if deps[0].Name != "lodash" || deps[0].Ecosystem != "npm" {
		t.Fatalf("unexpected dependency: %+v", deps[0])
	}
	if deps[0].SourceType != SourceTypeSBOM {
		t.Fatalf("expected SBOM source type, got %q", deps[0].SourceType)
	}
}

func TestExtractFromCycloneDXSyftFilename(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "clean-sbom", "app.cyclonedx.json")
	root := filepath.Dir(fixture)

	deps, err := extractFromSource(context.Background(), root, fixture, SourceTypeSBOM, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Name != "lodash" {
		t.Fatalf("unexpected deps: %+v", deps)
	}
}

func TestResolveScanTargetSBOMFile(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "fixtures", "clean-sbom", "bom.cdx.json")
	targets, err := resolveAuditTargets([]string{fixture})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || len(targets[0].pathsToExtract) != 1 {
		t.Fatalf("unexpected targets: %+v", targets)
	}
	if !isSBOMPath(targets[0].pathsToExtract[0]) {
		t.Fatalf("expected SBOM path in target: %s", targets[0].pathsToExtract[0])
	}
}
