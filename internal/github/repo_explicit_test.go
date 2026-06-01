package github

import "testing"

func TestIsExplicitAuditRef(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"github:projectdiscovery/depx", true},
		{"https://github.com/owner/repo", true},
		{"github.com/owner/repo", true},
		{"owner/repo", false},
		{"projectdiscovery/depx", false},
		{"./src/main", false},
	}
	for _, tc := range cases {
		if got := IsExplicitAuditRef(tc.in); got != tc.want {
			t.Fatalf("IsExplicitAuditRef(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSplitFullNameFallback(t *testing.T) {
	owner, name := splitFullName("", "acme", "my.repo")
	if owner != "acme" || name != "my.repo" {
		t.Fatalf("splitFullName fallback = %q/%q, want acme/my.repo", owner, name)
	}
}
