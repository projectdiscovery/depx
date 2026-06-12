package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func writeExcludeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exclude.txt")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadExcludeFileMatching(t *testing.T) {
	body := `# suppress known false positives
npm:left-pad
PyPI:Requests
*:internal-shared-lib

Maven:com.example:widget
`
	path := writeExcludeFile(t, body)
	set, err := LoadExcludeFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	cases := []struct {
		eco, name string
		want      bool
	}{
		{"npm", "left-pad", true},
		{"npm", "LEFT-PAD", true},                  // name match is case-insensitive
		{"PyPI", "requests", true},                 // entry name cased differently than dep
		{"python", "requests", true},               // ecosystem synonym for PyPI
		{"npm", "internal-shared-lib", true},       // wildcard
		{"crates.io", "internal-shared-lib", true}, // wildcard any ecosystem
		{"Maven", "com.example:widget", true},      // colon preserved in name
		{"npm", "left-pads", false},                // not an entry
		{"PyPI", "left-pad", false},                // right name, wrong ecosystem
		{"npm", "", false},
	}
	for _, tc := range cases {
		if got := set.Has(tc.eco, tc.name); got != tc.want {
			t.Errorf("Has(%q, %q) = %v, want %v", tc.eco, tc.name, got, tc.want)
		}
	}
}

func TestExcludeSetEmpty(t *testing.T) {
	var zero ExcludeSet
	if !zero.Empty() {
		t.Fatal("zero-value ExcludeSet should be empty")
	}
	if zero.Has("npm", "left-pad") {
		t.Fatal("empty set should not match anything")
	}
}

func TestLoadExcludeFileMalformed(t *testing.T) {
	path := writeExcludeFile(t, "npm:left-pad\nno-colon-here\n")
	if _, err := LoadExcludeFile(path); err == nil {
		t.Fatal("expected error for line without a colon")
	}

	path = writeExcludeFile(t, "npm:\n")
	if _, err := LoadExcludeFile(path); err == nil {
		t.Fatal("expected error for empty package name")
	}

	if _, err := LoadExcludeFile(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
