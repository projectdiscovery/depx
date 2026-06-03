package osv

import "testing"

func TestCampaignName(t *testing.T) {
	v := &Vulnerability{
		Details: "foo\n\nCampaign: 2026-05-apkeep\n",
	}
	if got := v.CampaignName(); got != "2026-05-apkeep" {
		t.Fatalf("got %q", got)
	}
}

func TestVulnPageURL(t *testing.T) {
	got := VulnPageURL("MAL-2026-3431")
	want := "https://osv.dev/vulnerability/MAL-2026-3431"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
