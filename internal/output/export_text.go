package output

import (
	"os"

	"github.com/projectdiscovery/depx/internal/audit"
)

// WriteAuditTextFile writes the human audit render without ANSI colors to path.
func WriteAuditTextFile(path string, result *audit.Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	o := Options{NoColor: true, Writer: f}
	writeAuditResults(o, result)
	return nil
}
