package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// prepareScalibrSBOMPath returns a path scalibr can parse. Syft and other tools
// often emit *.cyclonedx.json, which scalibr only accepts as *.cdx.json.
func prepareScalibrSBOMPath(absSource string) (string, func(), error) {
	lower := strings.ToLower(absSource)
	switch {
	case strings.HasSuffix(lower, ".cyclonedx.json"):
		return symlinkWithSuffix(absSource, ".cdx.json")
	case strings.HasSuffix(lower, ".cyclonedx.xml"):
		return symlinkWithSuffix(absSource, ".cdx.xml")
	default:
		return absSource, func() {}, nil
	}
}

func symlinkWithSuffix(src, suffix string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "depx-sbom-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	link := filepath.Join(dir, "sbom"+suffix)
	if err := os.Symlink(src, link); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("prepare sbom path: %w", err)
	}
	return link, cleanup, nil
}
