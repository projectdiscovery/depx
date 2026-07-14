package malindex

import "testing"

func TestVulnPageURL(t *testing.T) {
	got := VulnPageURL("MAL-2026-3431")
	want := "https://osv.dev/vulnerability/MAL-2026-3431"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := VulnPageURL("GHSCAN-MAL-a806cd7722ef"); got != "" {
		t.Fatalf("synthetic id must not link to osv.dev, got %q", got)
	}
	// Only MAL-* ids link to osv.dev; other families show their source name.
	if HasOSVDevPage("GHSA-xxxx-yyyy-zzzz") {
		t.Fatal("only MAL-* ids should be treated as osv.dev-hosted")
	}
}
