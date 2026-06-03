package osv

import "fmt"

// FirstRunCacheNote explains that the initial corpus download is stored locally.
const FirstRunCacheNote = "first run only — cached locally"

// WithFirstRunCacheNote appends the first-run cache hint to a spinner message.
func WithFirstRunCacheNote(msg string) string {
	return msg + " · " + FirstRunCacheNote
}

// FormatIndexDownloadProgress formats spinner text for malicious-package index sync.
func FormatIndexDownloadProgress(loaded, total int) string {
	switch {
	case total > 0:
		pct := int(float64(loaded) / float64(total) * 100)
		if pct > 100 {
			pct = 100
		}
		if loaded > total {
			loaded = total
		}
		return fmt.Sprintf("Downloading malicious package index… %d%% (%s/%s advisories)",
			pct, formatProgressCount(loaded), formatProgressCount(total))
	case loaded > 0:
		return fmt.Sprintf("Downloading malicious package index… %s advisories", formatProgressCount(loaded))
	default:
		return "Downloading malicious package corpus from OSV…"
	}
}

func formatProgressCount(n int) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.1fk", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}
