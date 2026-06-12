package cli

import "testing"

func TestNormalizePDStyleArgs(t *testing.T) {
	got := normalizePDStyleArgs([]string{"-version", "audit", "-update"})
	want := []string{"--version", "audit", "--update"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
