package osv

import "testing"

func TestWithFirstRunCacheNote(t *testing.T) {
	got := WithFirstRunCacheNote("Downloading malicious package corpus from OSV…")
	want := "Downloading malicious package corpus from OSV… · first run only — cached locally"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFormatIndexDownloadProgress(t *testing.T) {
	tests := []struct {
		loaded, total int
		want          string
	}{
		{0, 0, "Downloading malicious package corpus from OSV…"},
		{102_500, 0, "Downloading malicious package index… 102.5k advisories"},
		{113_250, 226_500, "Downloading malicious package index… 50% (113.2k/226.5k advisories)"},
		{226_500, 226_500, "Downloading malicious package index… 100% (226.5k/226.5k advisories)"},
	}
	for _, tc := range tests {
		if got := FormatIndexDownloadProgress(tc.loaded, tc.total); got != tc.want {
			t.Fatalf("FormatIndexDownloadProgress(%d, %d) = %q, want %q", tc.loaded, tc.total, got, tc.want)
		}
	}
}
