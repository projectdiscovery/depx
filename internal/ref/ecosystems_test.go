package ref

import "testing"

func TestHasExplicitEcosystem(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"apkeep", false},
		{"npm:lodash", true},
		{"pypi:requests", true},
		{"@scope/pkg", true},
		{"pkg:npm/lodash", true},
	}
	for _, tc := range tests {
		if got := HasExplicitEcosystem(tc.in); got != tc.want {
			t.Fatalf("HasExplicitEcosystem(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsKnownEcosystem(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"npm", true},
		{"PyPI", true},
		{"pypi", true},
		{"go", true},
		{"golang", true},
		{"cargo", true},
		{"crates.io", true},
		{"gem", true},
		{"Maven", true},
		{"boguseco", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := IsKnownEcosystem(tc.in); got != tc.want {
			t.Fatalf("IsKnownEcosystem(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseBare(t *testing.T) {
	name, ver, err := ParseBare("apkeep@1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if name != "apkeep" || ver != "1.2.3" {
		t.Fatalf("got %q@%q", name, ver)
	}
}
