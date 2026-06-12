package intel

import (
	"context"
	"strings"
	"time"

	"github.com/projectdiscovery/depx/internal/registry"
	"github.com/projectdiscovery/depx/internal/source"
)

// scheduleQuarantineRefresh runs quarantine network refresh; overridden in tests.
var scheduleQuarantineRefresh = func(fn func()) {
	go fn()
}

// scheduleFeedQuarantineRefresh warms the quarantine cache in the background.
// Feed rendering uses only on-disk cache; uncached npm packages may show MALICIOUS
// until a later feed run.
func scheduleFeedQuarantineRefresh(cacheDir, userAgent string, timeout time.Duration, entries []source.PackageEntry) {
	names := npmNamesNeedingQuarantineCheck(cacheDir, entries)
	if len(names) == 0 {
		return
	}
	scheduleQuarantineRefresh(func() {
		registry.RefreshNPMQuarantineCache(context.Background(), cacheDir, userAgent, timeout, names)
	})
}

func npmNamesNeedingQuarantineCheck(cacheDir string, entries []source.PackageEntry) []string {
	seen := map[string]struct{}{}
	names := make([]string, 0)
	for _, entry := range entries {
		if !isNPMFeedEcosystem(entry.Ecosystem) {
			continue
		}
		name := strings.TrimSpace(entry.Name)
		if name == "" || registry.HasQuarantineCacheEntry(cacheDir, "npm", name) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func isNPMFeedEcosystem(ecosystem string) bool {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "javascript", "js":
		return true
	default:
		return false
	}
}
