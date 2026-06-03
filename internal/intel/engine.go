package intel

import (
	"fmt"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/pd"
	"github.com/projectdiscovery/depx/internal/sync"
)

func newSyncEngine(version string, cfg *config.Config) *sync.Engine {
	source := "osv"
	if pd.Enabled() {
		source = "pd"
	}
	return sync.NewEngine(sync.Config{
		CacheDir:  cfg.CacheDir,
		UserAgent: fmt.Sprintf("depx/%s (+https://github.com/projectdiscovery/depx)", version),
		Timeout:   cfg.Timeout,
		Source:    source,
	})
}
