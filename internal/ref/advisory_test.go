package ref

import "testing"

func TestIsAdvisoryID(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"MAL-2026-3431", true},
		{"GHSA-xxxx-yyyy-zzzz", true},
		{"CVE-2024-12345", true},
		{"apkeep", false},
		{"npm:lodash", false},
		{"MAL", false},
	} {
		if got := IsAdvisoryID(tc.in); got != tc.want {
			t.Fatalf("IsAdvisoryID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
