package osv

import "testing"

func TestParseModifiedLine(t *testing.T) {
	entry, ok := parseModifiedLine("2026-05-25T09:46:42.410038999Z,npm/MAL-2026-4343")
	if !ok {
		t.Fatal("expected ok")
	}
	if entry.Ecosystem != "npm" || entry.ID != "MAL-2026-4343" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
}

func TestIsMaliciousID(t *testing.T) {
	if !IsMaliciousID("MAL-2026-1") {
		t.Fatal("expected malicious")
	}
	if IsMaliciousID("CVE-2024-1") {
		t.Fatal("expected not malicious")
	}
}

func TestMaliciousVulns(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "MAL-1"},
		{ID: "CVE-1"},
	}
	out := MaliciousVulns(vulns)
	if len(out) != 1 || out[0].ID != "MAL-1" {
		t.Fatalf("unexpected filter: %+v", out)
	}
}
