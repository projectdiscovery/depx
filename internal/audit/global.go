package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type pkgJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// collectGlobalDependencies finds globally installed packages without lockfile parsing.
func collectGlobalDependencies(home string) []Dependency {
	if home == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var deps []Dependency
	add := func(dep Dependency) {
		if dep.Name == "" || dep.Ecosystem == "" {
			return
		}
		key := dep.Ecosystem + "|" + dep.Name + "|" + dep.Version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		deps = append(deps, dep)
	}

	for _, root := range npmGlobalRoots(home) {
		for _, dep := range auditNpmNodeModules(root) {
			add(dep)
		}
	}
	for _, dep := range scanGoModCache(filepath.Join(home, "go", "pkg", "mod")) {
		add(dep)
	}
	return deps
}

func npmGlobalRoots(home string) []string {
	roots := []string{
		filepath.Join(home, ".npm-global", "lib", "node_modules"),
	}
	if nvm, err := filepath.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "lib", "node_modules")); err == nil {
		roots = append(roots, nvm...)
	}
	if fnm, err := filepath.Glob(filepath.Join(home, ".fnm", "node-versions", "*", "installation", "lib", "node_modules")); err == nil {
		roots = append(roots, fnm...)
	}
	if pnpm, err := filepath.Glob(filepath.Join(home, ".local", "share", "pnpm", "*", "node_modules")); err == nil {
		roots = append(roots, pnpm...)
	}
	return roots
}

func auditNpmNodeModules(root string) []Dependency {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	deps := make([]Dependency, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		pkgPath := filepath.Join(root, entry.Name(), "package.json")
		data, err := os.ReadFile(pkgPath)
		if err != nil {
			continue
		}
		var meta pkgJSON
		if err := json.Unmarshal(data, &meta); err != nil || meta.Name == "" {
			continue
		}
		deps = append(deps, Dependency{
			Ecosystem: "npm",
			Name:      meta.Name,
			Version:   meta.Version,
			Source:    root + " (global)",
		})
	}
	return deps
}

func scanGoModCache(root string) []Dependency {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil
	}
	var deps []Dependency
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.Contains(path, string(filepath.Separator)+"cache"+string(filepath.Separator)) {
				return filepath.SkipDir
			}
			name := d.Name()
			if idx := strings.LastIndex(name, "@v"); idx > 0 && idx < len(name)-2 {
				mod := name[:idx]
				ver := strings.TrimPrefix(name[idx+1:], "v")
				if mod != "" && ver != "" {
					deps = append(deps, Dependency{
						Ecosystem: "Go",
						Name:      mod,
						Version:   ver,
						Source:    filepath.Dir(path) + " (go mod cache)",
					})
				}
				return filepath.SkipDir
			}
			return nil
		}
		return nil
	})
	return deps
}
