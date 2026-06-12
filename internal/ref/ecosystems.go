package ref

import (
	"strings"

	"github.com/projectdiscovery/depx/internal/apperr"
)

// CheckEcosystems lists ecosystems queried for bare package names (no -e / no prefix).
var CheckEcosystems = []string{
	"npm",
	"PyPI",
	"Go",
	"crates.io",
	"RubyGems",
	"Maven",
}

func isKnownEcosystem(eco string) bool {
	eco = normalizeEcosystem(eco)
	for _, candidate := range CheckEcosystems {
		if eco == candidate {
			return true
		}
	}
	return false
}

// IsKnownEcosystem reports whether eco names a supported ecosystem, accepting
// common synonyms (e.g. "golang" -> Go, "pypi" -> PyPI, "cargo" -> crates.io).
func IsKnownEcosystem(eco string) bool {
	return isKnownEcosystem(eco)
}

// HasExplicitEcosystem reports whether the input already pins a single ecosystem.
func HasExplicitEcosystem(input string) bool {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "pkg:") {
		return true
	}
	if strings.HasPrefix(input, "@") {
		return true
	}
	if idx := strings.Index(input, ":"); idx > 0 {
		return isKnownEcosystem(input[:idx])
	}
	return false
}

// ParseBare splits a bare package name (no ecosystem prefix) into name and version.
func ParseBare(input string) (name, version string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", apperr.Usage("package reference is required")
	}
	if HasExplicitEcosystem(input) {
		return "", "", apperr.Usage("expected bare package name without ecosystem prefix")
	}
	name, version = splitNameVersion(input)
	return name, version, nil
}
