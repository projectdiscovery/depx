package malindex

import "testing"

func TestVulnPageURL(t *testing.T) {
	got := VulnPageURL("MAL-2026-3431")
	want := "https://osv.dev/vulnerability/MAL-2026-3431"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
