package audit

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	"github.com/google/osv-scalibr/purl"
)

func spdxPkg(purlType, namespace, name, version string) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purlType,
		Metadata: &spdxmeta.Metadata{
			PURL: &purl.PackageURL{
				Type:      purlType,
				Namespace: namespace,
				Name:      name,
				Version:   version,
			},
		},
	}
}

// Regression: SBOM extractors drop the PURL namespace from Package.Name, so a
// scoped npm package such as @babel/helper-annotate-as-pure arrived as the bare
// "helper-annotate-as-pure" and collided with an unrelated malicious package of
// that bare name. packageName must rebuild the scoped/qualified name.
func TestPackageNameRebuildsNamespace(t *testing.T) {
	cases := []struct {
		name     string
		pkg      *extractor.Package
		expected string
	}{
		{
			name:     "scoped npm keeps @scope",
			pkg:      spdxPkg("npm", "@babel", "helper-annotate-as-pure", "7.0.0"),
			expected: "@babel/helper-annotate-as-pure",
		},
		{
			name:     "unscoped npm unchanged",
			pkg:      spdxPkg("npm", "", "left-pad", "1.0.0"),
			expected: "left-pad",
		},
		{
			name:     "golang module path joined with slash",
			pkg:      spdxPkg("golang", "github.com/foo", "bar", "1.2.3"),
			expected: "github.com/foo/bar",
		},
		{
			name:     "maven joined with colon",
			pkg:      spdxPkg("maven", "org.apache", "commons", "1.0"),
			expected: "org.apache:commons",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := packageName(tc.pkg); got != tc.expected {
				t.Fatalf("packageName = %q, want %q", got, tc.expected)
			}
		})
	}
}

// Lockfile extractors store the already-qualified name in Package.Name while the
// PURL carries the split namespace+name. packageName must NOT re-prepend the
// namespace (which would double it, e.g. "@babel/@babel/foo").
func TestPackageNameKeepsAlreadyQualifiedName(t *testing.T) {
	pkg := spdxPkg("npm", "@babel", "foo", "1.0.0")
	pkg.Name = "@babel/foo" // already qualified, unlike the bare PURL name
	if got := packageName(pkg); got != "@babel/foo" {
		t.Fatalf("packageName = %q, want %q", got, "@babel/foo")
	}
}

func TestPackageNameNilPURLFallsBackToName(t *testing.T) {
	pkg := &extractor.Package{Name: "some-pkg", Version: "1.0.0"} // PURLType empty -> PURL() nil
	if got := packageName(pkg); got != "some-pkg" {
		t.Fatalf("packageName = %q, want %q", got, "some-pkg")
	}
}

// Regression: the SPDX extractor leaves Package.Version empty and only records
// the version in the PURL. packageVersion must recover it, otherwise GitHub SBOM
// audits lose the version (hidden from output and unable to match
// version-specific advisories).
func TestPackageVersionRecoveredFromPURL(t *testing.T) {
	pkg := spdxPkg("npm", "", "simple-project-pkg-b", "1.0.0")
	pkg.Version = "" // SPDX extractor never sets this
	if got := packageVersion(pkg); got != "1.0.0" {
		t.Fatalf("packageVersion = %q, want %q", got, "1.0.0")
	}
}

func TestPackageVersionPrefersExplicitField(t *testing.T) {
	pkg := spdxPkg("npm", "", "left-pad", "9.9.9")
	pkg.Version = "1.2.3" // explicit field wins
	if got := packageVersion(pkg); got != "1.2.3" {
		t.Fatalf("packageVersion = %q, want %q", got, "1.2.3")
	}
}
