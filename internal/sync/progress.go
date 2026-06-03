package sync

import (
	"strings"
)

func indexSyncProgress(cacheDir string) (loaded, total int) {
	loaded = countVulnBlobs(cacheDir)
	m, err := loadManifest(cacheDir, "osv")
	if err != nil || m == nil {
		return loaded, 0
	}
	if m.Catalog.MaliciousCount > 0 {
		total = m.Catalog.MaliciousCount
	} else {
		for id, rec := range m.Entries {
			if !strings.HasPrefix(id, "MAL-") {
				continue
			}
			switch rec.Status {
			case EntryPending, EntryReady:
				total++
			}
		}
	}
	if total == 0 && loaded > 0 {
		total = loaded
	}
	return loaded, total
}
