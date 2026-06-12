package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func sampleDeps() []Dependency {
	return []Dependency{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"},
		{Ecosystem: "PyPI", Name: "requests", Version: "2.31.0"},
		{Ecosystem: "Maven", Name: "com.google.guava:guava", Version: "33.0.0"},
	}
}

func TestResolveSBOMFormat(t *testing.T) {
	cases := []struct {
		flag, path, want string
	}{
		{"", "out.cdx.json", "cyclonedx"},
		{"", "out.spdx.json", "spdx"},
		{"cyclonedx", "out.json", "cyclonedx"},
		{"cdx", "out.json", "cyclonedx"},
		{"spdx", "out.json", "spdx"},
	}
	for _, c := range cases {
		got, err := resolveSBOMFormat(c.flag, c.path)
		if err != nil {
			t.Fatalf("resolveSBOMFormat(%q,%q): %v", c.flag, c.path, err)
		}
		if got != c.want {
			t.Fatalf("resolveSBOMFormat(%q,%q) = %q, want %q", c.flag, c.path, got, c.want)
		}
	}
	if _, err := resolveSBOMFormat("bogus", "out.json"); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestPurlFor(t *testing.T) {
	cases := map[string]string{
		"npm|left-pad|1.3.0":                  "pkg:npm/left-pad@1.3.0",
		"PyPI|requests|2.31.0":                "pkg:pypi/requests@2.31.0",
		"Go|github.com/foo/bar|1.0.0":         "pkg:golang/github.com/foo/bar@1.0.0",
		"Maven|com.google.guava:guava|33.0.0": "pkg:maven/com.google.guava/guava@33.0.0",
	}
	for in, want := range cases {
		eco, name, version := in[:index(in, '|')], "", ""
		rest := in[index(in, '|')+1:]
		name = rest[:index(rest, '|')]
		version = rest[index(rest, '|')+1:]
		if got := purlFor(eco, name, version); got != want {
			t.Fatalf("purlFor(%q,%q,%q) = %q, want %q", eco, name, version, got, want)
		}
	}
	if got := purlFor("unknowneco-xyz", "n", "1"); got == "" {
		t.Fatal("expected fallback purl for unknown ecosystem")
	}
}

func index(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func TestWriteSBOMCycloneDX(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.cdx.json")

	written, err := writeSBOM(path, "", "1.2.3", sampleDeps())
	if err != nil {
		t.Fatalf("writeSBOM: %v", err)
	}
	if written != path {
		t.Fatalf("written path = %q, want %q", written, path)
	}

	raw, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Fatalf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}
	comps, ok := doc["components"].([]any)
	if !ok || len(comps) != 3 {
		t.Fatalf("expected 3 components, got %v", doc["components"])
	}
}

func TestWriteSBOMSPDX(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.spdx.json")

	if _, err := writeSBOM(path, "", "1.2.3", sampleDeps()); err != nil {
		t.Fatalf("writeSBOM: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sbom: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("spdxVersion = %v, want SPDX-2.3", doc["spdxVersion"])
	}
	pkgs, ok := doc["packages"].([]any)
	if !ok || len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %v", doc["packages"])
	}
}

func TestWriteSBOMCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deep", "out.cdx.json")
	if _, err := writeSBOM(path, "cyclonedx", "", sampleDeps()); err != nil {
		t.Fatalf("writeSBOM: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("sbom not written to nested dir: %v", err)
	}
}
