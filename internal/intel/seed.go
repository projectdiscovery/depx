package intel

import (
	"github.com/projectdiscovery/depx/internal/bundle"
	"github.com/projectdiscovery/depx/internal/pd"
)

func seedIntelCache(cacheDir, source string) error {
	_, err := bundle.SeedIfNeeded(cacheDir, source)
	return err
}

// SeedEmbeddedCache extracts embedded offline bundles before background sync starts.
func SeedEmbeddedCache(cacheDir string) error {
	source := "osv"
	if pd.Enabled() {
		source = "pd"
	}
	return seedIntelCache(cacheDir, source)
}
