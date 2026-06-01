package ref

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/depx/internal/apperr"
)

var ecosystemAliases = map[string]string{
	"cargo":  "crates.io",
	"gem":    "RubyGems",
	"golang": "Go",
	"pypi":   "PyPI",
	"npm":    "npm",
	"go":     "Go",
	"crates": "crates.io",
	"ruby":   "RubyGems",
}

type PackageRef struct {
	Ecosystem string
	Name      string
	Version   string
	Raw       string
}

func Parse(input, defaultEcosystem string) (PackageRef, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return PackageRef{}, apperr.Usage("package reference is required")
	}

	if strings.HasPrefix(input, "pkg:") {
		return parsePURL(input)
	}

	if strings.HasPrefix(input, "@") {
		name, version := splitNameVersion(input)
		return PackageRef{
			Ecosystem: "npm",
			Name:      name,
			Version:   version,
			Raw:       input,
		}, nil
	}

	if idx := strings.Index(input, ":"); idx > 0 {
		eco := normalizeEcosystem(input[:idx])
		if isKnownEcosystem(eco) {
			rest := input[idx+1:]
			name, version := splitNameVersion(rest)
			if name == "" {
				return PackageRef{}, apperr.Usage("package name is required after ecosystem prefix")
			}
			return PackageRef{
				Ecosystem: eco,
				Name:      name,
				Version:   version,
				Raw:       input,
			}, nil
		}
	}

	if defaultEcosystem == "" {
		return PackageRef{}, apperr.Usage("ecosystem is required for bare package names; use -e or ecosystem:name")
	}
	name, version := splitNameVersion(input)
	return PackageRef{
		Ecosystem: normalizeEcosystem(defaultEcosystem),
		Name:      name,
		Version:   version,
		Raw:       input,
	}, nil
}

func parsePURL(purl string) (PackageRef, error) {
	// pkg:npm/foo@1.0.0 or pkg:npm/%40scope/pkg@1.0.0
	rest := strings.TrimPrefix(purl, "pkg:")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		return PackageRef{}, apperr.Usage("invalid purl: " + purl)
	}
	eco := normalizeEcosystem(parts[0])
	name, version := splitNameVersion(parts[1])
	return PackageRef{
		Ecosystem: eco,
		Name:      name,
		Version:   version,
		Raw:       purl,
	}, nil
}

func splitNameVersion(s string) (string, string) {
	if at := strings.LastIndex(s, "@"); at > 0 {
		return s[:at], s[at+1:]
	}
	return s, ""
}

func normalizeEcosystem(eco string) string {
	eco = strings.TrimSpace(eco)
	if mapped, ok := ecosystemAliases[strings.ToLower(eco)]; ok {
		return mapped
	}
	switch strings.ToLower(eco) {
	case "crates.io":
		return "crates.io"
	case "rubygems":
		return "RubyGems"
	default:
		return eco
	}
}

func (r PackageRef) String() string {
	if r.Version != "" {
		return fmt.Sprintf("%s:%s@%s", strings.ToLower(r.Ecosystem), r.Name, r.Version)
	}
	return fmt.Sprintf("%s:%s", strings.ToLower(r.Ecosystem), r.Name)
}

func (r PackageRef) OSVPackage() map[string]string {
	return map[string]string{
		"name":      r.Name,
		"ecosystem": r.Ecosystem,
	}
}
