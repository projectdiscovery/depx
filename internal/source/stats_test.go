package source

import (
	"testing"
	"time"
)

func TestComputeWindowStats(t *testing.T) {
	now := time.Now().UTC()
	entries := []PackageEntry{
		{Ecosystem: "npm", Name: "a", Published: now.Add(-2 * 24 * time.Hour), Campaign: "camp-a"},
		{Ecosystem: "npm", Name: "b", Published: now.Add(-10 * 24 * time.Hour), Withdrawn: true},
		{Ecosystem: "PyPI", Name: "c", Published: now.Add(-40 * 24 * time.Hour), Aliases: []string{"GHSA-1"}},
	}

	st := ComputeWindowStats(entries)
	if st.Advisories != 3 || st.UniquePackages != 3 {
		t.Fatalf("counts: advisories=%d unique=%d", st.Advisories, st.UniquePackages)
	}
	if st.Withdrawn != 1 || st.WithAliases != 1 {
		t.Fatalf("withdrawn=%d aliases=%d", st.Withdrawn, st.WithAliases)
	}
	if len(st.Ecosystems) == 0 || st.Ecosystems[0].Label != "npm" || st.Ecosystems[0].Count != 2 {
		t.Fatalf("ecosystems: %+v", st.Ecosystems)
	}
}

func TestComputeWindowStatsNamespaces(t *testing.T) {
	now := time.Now().UTC()
	entries := []PackageEntry{
		{Ecosystem: "npm", Name: "@acme/logger", Published: now},
		{Ecosystem: "npm", Name: "@acme/utils", Published: now},
		{Ecosystem: "npm", Name: "lodash", Published: now}, // unscoped -> no namespace
		{Ecosystem: "Go", Name: "github.com/evil/pkg", Published: now},
		{Ecosystem: "Maven", Name: "com.evil:lib", Published: now},
		{Ecosystem: "PyPI", Name: "discord-ban", Published: now}, // no real scope
	}

	st := ComputeWindowStats(entries)
	if len(st.Namespaces) == 0 {
		t.Fatalf("expected namespaces, got none")
	}
	if st.Namespaces[0].Label != "@acme" || st.Namespaces[0].Count != 2 {
		t.Fatalf("top namespace: %+v", st.Namespaces)
	}

	got := map[string]int{}
	for _, b := range st.Namespaces {
		got[b.Label] = b.Count
	}
	for _, want := range []string{"@acme", "github.com/evil", "com.evil"} {
		if got[want] == 0 {
			t.Fatalf("missing namespace %q in %+v", want, st.Namespaces)
		}
	}
	for _, unwanted := range []string{"lodash", "discord"} {
		if _, ok := got[unwanted]; ok {
			t.Fatalf("%q should not produce a namespace: %+v", unwanted, st.Namespaces)
		}
	}
}

func TestNamespaceKey(t *testing.T) {
	cases := []struct {
		eco, name, want string
	}{
		{"npm", "@scope/a", "@scope"},
		{"npm", "plain", ""},
		{"Go", "github.com/org/repo", "github.com/org"},
		{"Go", "single", ""},
		{"Maven", "com.group:artifact", "com.group"},
		{"PyPI", "discord-ban", ""}, // PyPI has no scopes; do not split on "-"
		{"PyPI", "foo", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		if got := namespaceKey(tc.eco, tc.name); got != tc.want {
			t.Errorf("namespaceKey(%q,%q)=%q want %q", tc.eco, tc.name, got, tc.want)
		}
	}
}
