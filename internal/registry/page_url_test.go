package registry

import "testing"

func TestPackagePageURL(t *testing.T) {
	tests := []struct {
		eco, name, want string
	}{
		{"npm", "lodash", "https://www.npmjs.com/package/lodash"},
		{"npm", "@fake-registry/a", "https://www.npmjs.com/package/@fake-registry/a"},
		{"PyPI", "requests", "https://pypi.org/project/requests/"},
		{"Go", "github.com/foo/bar", "https://pkg.go.dev/github.com/foo/bar"},
		{"crates.io", "serde", "https://crates.io/crates/serde"},
		{"RubyGems", "rails", "https://rubygems.org/gems/rails"},
		{"NuGet", "Newtonsoft.Json", "https://www.nuget.org/packages/Newtonsoft.Json"},
		{"Maven", "org.example:artifact", "https://central.sonatype.com/artifact/org.example/artifact"},
		{"Maven", "com.example:artifact:jar", "https://central.sonatype.com/artifact/com.example/artifact"},
		{"unknown", "foo", ""},
	}
	for _, tt := range tests {
		if got := PackagePageURL(tt.eco, tt.name); got != tt.want {
			t.Fatalf("PackagePageURL(%q, %q) = %q, want %q", tt.eco, tt.name, got, tt.want)
		}
	}
}
