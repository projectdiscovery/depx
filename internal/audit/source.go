package audit

import (
	"path/filepath"
	"strings"
)

type SourceType string

const (
	SourceTypeLockfile SourceType = "lockfile"
	SourceTypeSBOM     SourceType = "sbom"
)

var sbomPlugins = []string{
	"sbom/cdx",
	"sbom/spdx",
}

func sourceTypeForPath(path string) (SourceType, bool) {
	if isLockfilePath(path) {
		return SourceTypeLockfile, true
	}
	if isSBOMPath(path) {
		return SourceTypeSBOM, true
	}
	return "", false
}

func isAuditSourcePath(path string) bool {
	_, ok := sourceTypeForPath(path)
	return ok
}

// isSBOMPath mirrors osv-scalibr sbom/cdx and sbom/spdx FileRequired patterns.
func isSBOMPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "bom.json", "bom.xml":
		return true
	}
	for _, ext := range []string{
		".cdx.json", ".cdx.xml",
		".cyclonedx.json", ".cyclonedx.xml",
		".spdx.json", ".spdx", ".spdx.yml", ".spdx.rdf", ".spdx.rdf.xml",
	} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

func pluginsForSource(sourceType SourceType) []string {
	if sourceType == SourceTypeSBOM {
		return sbomPlugins
	}
	return lockfilePlugins
}

func sourceKindLabel(sourceType SourceType) string {
	if sourceType == SourceTypeSBOM {
		return "SBOM"
	}
	return "lockfile"
}
