package audit

import "testing"

func TestIsSBOMPath(t *testing.T) {
	yes := []string{
		"bom.json",
		"bom.xml",
		"release.cdx.json",
		"image.cdx.xml",
		"release.cyclonedx.json",
		"release.cyclonedx.xml",
		"sbom.spdx.json",
		"sbom.spdx",
		"sbom.spdx.yml",
		"sbom.spdx.rdf",
		"sbom.spdx.rdf.xml",
	}
	for _, name := range yes {
		if !isSBOMPath("/tmp/" + name) {
			t.Fatalf("expected SBOM path for %q", name)
		}
	}
	no := []string{
		"package-lock.json",
		"random.json",
		"sbom.json",
		"notes.spdx.xsl",
	}
	for _, name := range no {
		if isSBOMPath("/tmp/" + name) {
			t.Fatalf("did not expect SBOM path for %q", name)
		}
	}
}

func TestSourceTypeForPath(t *testing.T) {
	if got, ok := sourceTypeForPath("/tmp/bom.json"); !ok || got != SourceTypeSBOM {
		t.Fatalf("bom.json: got %q ok=%v", got, ok)
	}
	if got, ok := sourceTypeForPath("/tmp/package-lock.json"); !ok || got != SourceTypeLockfile {
		t.Fatalf("package-lock.json: got %q ok=%v", got, ok)
	}
	if _, ok := sourceTypeForPath("/tmp/readme.md"); ok {
		t.Fatal("readme.md should not be a scan source")
	}
}
