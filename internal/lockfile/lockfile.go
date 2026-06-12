package lockfile

import "strings"

// RootNames are lockfiles fetched from a repository root or discovered locally.
var RootNames = []string{
	"package-lock.json",
	"npm-shrinkwrap.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"poetry.lock",
	"pipfile.lock",
	"go.mod",
	"cargo.lock",
	"gemfile.lock",
	"pom.xml",
	"gradle.lockfile",
	"buildscript-gradle.lockfile",
}

var rootSet map[string]struct{}

func init() {
	rootSet = make(map[string]struct{}, len(RootNames))
	for _, name := range RootNames {
		rootSet[strings.ToLower(name)] = struct{}{}
	}
}

func IsRootName(name string) bool {
	_, ok := rootSet[strings.ToLower(name)]
	return ok
}

// Ecosystem returns the OSV ecosystem label for a root lockfile name.
func Ecosystem(name string) string {
	switch strings.ToLower(name) {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml":
		return "npm"
	case "poetry.lock", "pipfile.lock":
		return "PyPI"
	case "go.mod", "go.sum":
		return "Go"
	case "cargo.lock":
		return "crates.io"
	case "gemfile.lock":
		return "RubyGems"
	case "pom.xml":
		return "Maven"
	case "gradle.lockfile", "buildscript-gradle.lockfile":
		return "Maven"
	default:
		return ""
	}
}
