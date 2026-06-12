package github

import "testing"

func TestParseRepo(t *testing.T) {
	cases := []struct {
		in       string
		wantOK   bool
		wantRepo Repo
	}{
		{"github:projectdiscovery/depx", true, Repo{"projectdiscovery", "depx"}},
		{"gh:owner/repo", true, Repo{"owner", "repo"}},
		{"https://github.com/owner/repo", true, Repo{"owner", "repo"}},
		{"https://github.com/owner/repo.git", true, Repo{"owner", "repo"}},
		{"github:google/grinder.dart", true, Repo{"google", "grinder.dart"}},
		{"github:google/google.github.io", true, Repo{"google", "google.github.io"}},
		{"github.com/owner/repo", true, Repo{"owner", "repo"}},
		{"www.github.com/owner/repo", true, Repo{"owner", "repo"}},
		{"projectdiscovery/dnsx", true, Repo{"projectdiscovery", "dnsx"}},
		{"owner/repo/extra", false, Repo{}},
		{"https://github.com/owner/repo/tree/main", false, Repo{}},
		{"./local/path", false, Repo{}},
		{"npm:lodash", false, Repo{}},
		{"github:", false, Repo{}},
		{"projectdiscovery", false, Repo{}},
		{"/Users/geekboy", false, Repo{}},
		{"/home/user", false, Repo{}},
		{"/Users/geekboy/GitHub/depx", false, Repo{}},
	}
	for _, tc := range cases {
		got, ok := ParseRepo(tc.in)
		if ok != tc.wantOK {
			t.Fatalf("ParseRepo(%q) ok=%v want %v", tc.in, ok, tc.wantOK)
		}
		if ok && got != tc.wantRepo {
			t.Fatalf("ParseRepo(%q) = %+v want %+v", tc.in, got, tc.wantRepo)
		}
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in        string
		wantErr   bool
		wantOwner string
		wantName  string
	}{
		{"https://github.com/projectdiscovery/dnsx", false, "projectdiscovery", "dnsx"},
		{"https://github.com/projectdiscovery/dnsx.git", false, "projectdiscovery", "dnsx"},
		{"https://github.com/hooli-corp-tech", false, "hooli-corp-tech", ""},
		{"https://github.com/hooli-corp-tech/", false, "hooli-corp-tech", ""},
		{"github.com/hooli-corp-tech", false, "hooli-corp-tech", ""},
		{"projectdiscovery/dnsx", false, "projectdiscovery", "dnsx"},
		{"projectdiscovery", false, "projectdiscovery", ""},
		{"https://github.com/owner/repo/tree/main", true, "", ""},
		{"", true, "", ""},
		{"asdsada", false, "asdsada", ""},
	}
	for _, tc := range cases {
		got, err := ParseTarget(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseTarget(%q) expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", tc.in, err)
		}
		if got.Owner != tc.wantOwner || got.Name != tc.wantName {
			t.Fatalf("ParseTarget(%q) = %+v want owner=%q name=%q", tc.in, got, tc.wantOwner, tc.wantName)
		}
	}
}

func TestDisplayTargets(t *testing.T) {
	got, err := DisplayTargets([]string{"projectdiscovery"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "github.com/projectdiscovery" {
		t.Fatalf("DisplayTargets(org) = %v", got)
	}

	got, err = DisplayTargets([]string{"projectdiscovery/nuclei", "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "github.com/projectdiscovery/nuclei" || got[1] != "github.com/acme" {
		t.Fatalf("DisplayTargets(mixed) = %v", got)
	}
}

func TestDisplayOwners(t *testing.T) {
	got := DisplayOwners([]Repo{
		{Owner: "projectdiscovery", Name: "nuclei"},
		{Owner: "ehsandeep", Name: "app"},
		{Owner: "projectdiscovery", Name: "dnsx"},
	})
	want := []string{"github.com/ehsandeep", "github.com/projectdiscovery"}
	if len(got) != len(want) {
		t.Fatalf("DisplayOwners = %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("DisplayOwners = %v want %v", got, want)
		}
	}
}

func TestDisplayTarget(t *testing.T) {
	if got := DisplayTarget("github:acme/app"); got != "github.com/acme/app" {
		t.Fatalf("DisplayTarget github ref = %q", got)
	}
	if got := DisplayTarget("https://github.com/acme/app"); got != "github.com/acme/app" {
		t.Fatalf("DisplayTarget URL = %q", got)
	}
	if got := DisplayTarget("https://github.com/acme/app.git"); got != "github.com/acme/app" {
		t.Fatalf("DisplayTarget URL with .git = %q", got)
	}
	if got := DisplayTarget("/tmp/project"); got != "/tmp/project" {
		t.Fatalf("DisplayTarget path = %q", got)
	}
}

func TestRepoAuditRef(t *testing.T) {
	repo := Repo{Owner: "acme", Name: "app"}
	if repo.AuditRef() != "github:acme/app" {
		t.Fatalf("unexpected audit ref: %s", repo.AuditRef())
	}
	if repo.URL() != "https://github.com/acme/app" {
		t.Fatalf("unexpected url: %s", repo.URL())
	}
}
