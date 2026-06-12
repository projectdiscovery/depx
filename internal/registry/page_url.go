package registry

import (
	"fmt"
	"net/url"
	"strings"
)

// PackagePageURL returns a human-facing registry page for a package, if known.
func PackagePageURL(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	switch normalizePageEcosystem(ecosystem) {
	case "npm":
		return "https://www.npmjs.com/package/" + npmPackagePath(name)
	case "pypi":
		return "https://pypi.org/project/" + url.PathEscape(normalizePyPIName(name)) + "/"
	case "go":
		return "https://pkg.go.dev/" + name
	case "crates.io":
		return "https://crates.io/crates/" + url.PathEscape(name)
	case "rubygems":
		return "https://rubygems.org/gems/" + url.PathEscape(name)
	case "nuget":
		return "https://www.nuget.org/packages/" + url.PathEscape(name)
	case "maven":
		return mavenPackagePageURL(name)
	default:
		return ""
	}
}

func normalizePageEcosystem(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "npm", "javascript", "js":
		return "npm"
	case "pypi", "python":
		return "pypi"
	case "go", "golang":
		return "go"
	case "crates.io", "cargo", "rust", "crates":
		return "crates.io"
	case "rubygems", "ruby", "gem":
		return "rubygems"
	case "nuget":
		return "nuget"
	case "maven":
		return "maven"
	default:
		return strings.ToLower(eco)
	}
}

func npmPackagePath(name string) string {
	// Scoped npm packages use literal @scope/name in the website path.
	return strings.ReplaceAll(name, " ", "%20")
}

func normalizePyPIName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

func mavenPackagePageURL(name string) string {
	parts := strings.SplitN(name, ":", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return fmt.Sprintf("https://central.sonatype.com/artifact/%s/%s", url.PathEscape(parts[0]), url.PathEscape(parts[1]))
}
