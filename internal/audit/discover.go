package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/projectdiscovery/depx/internal/lockfile"
)

var skipDirNames = map[string]struct{}{
	".git":         {},
	".hg":          {},
	".svn":         {},
	".next":        {},
	".turbo":       {},
	".cache":       {},
	".pnpm-store":  {},
	".venv":        {},
	".vscode":      {},
	".idea":        {},
	"node_modules": {},
	"vendor":       {},
	"dist":         {},
	"build":        {},
	"out":          {},
	"target":       {},
	"__pycache__":  {},
	"venv":         {},
	"coverage":     {},
	"tmp":          {},
	"temp":         {},
}

var homeTopLevelSkip = map[string]struct{}{
	"Library":      {},
	"Applications": {},
	"Pictures":     {},
	"Movies":       {},
	"Music":        {},
	"Public":       {},
	".Trash":       {},
	"Parallels":    {},
}

const homeWalkWorkers = 12

type auditTarget struct {
	root           string
	pathsToExtract []string
	sourceLabels   map[string]string
}

func defaultAuditPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return []string{"."}
	}
	return []string{home}
}

func isLockfilePath(path string) bool {
	return lockfile.IsRootName(filepath.Base(path))
}

func shouldSkipDir(name string) bool {
	_, ok := skipDirNames[strings.ToLower(name)]
	return ok
}

func shouldSkipDirPath(path string) bool {
	name := filepath.Base(path)
	if shouldSkipDir(name) {
		return true
	}
	p := filepath.ToSlash(path)
	switch {
	case strings.Contains(p, "/go/pkg/mod/"):
		return true
	case strings.Contains(p, "/go/pkg/sumdb/"):
		return true
	case strings.Contains(p, "/go/pkg/mod/cache/"):
		return true
	case strings.Contains(p, "/.npm/_cacache"):
		return true
	case strings.Contains(p, "/Library/Caches/"):
		return true
	case strings.Contains(p, "/Library/Logs/"):
		return true
	case strings.Contains(p, "/Library/Application Support/"):
		return true
	case strings.Contains(p, "/.local/share/Trash/"):
		return true
	}
	return false
}

func resolveAuditTargets(paths []string) ([]auditTarget, error) {
	return resolveAuditTargetsWithProgress(paths, nil)
}

func resolveAuditTargetsWithProgress(paths []string, prog *Progress) ([]auditTarget, error) {
	if len(paths) == 0 {
		paths = defaultAuditPaths()
	}
	targets := make([]auditTarget, 0, len(paths))
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if isAuditSourcePath(abs) {
				targets = append(targets, auditTarget{
					root:           filepath.Dir(abs),
					pathsToExtract: []string{abs},
				})
				continue
			}
			return nil, fmt.Errorf("unsupported audit path %q (expected lockfile, SBOM, or directory)", abs)
		}
		var lockfiles []string
		if isHomeRoot(abs) {
			lockfiles, err = discoverLockfilesHome(abs, func(dirs int, current string) {
				prog.discover(dirs, current)
			})
		} else {
			lockfiles, err = discoverLockfiles(abs, func(dirs int, current string) {
				prog.discover(dirs, current)
			})
		}
		if err != nil {
			return nil, err
		}
		if prog != nil {
			prog.discovered(len(lockfiles), abs)
		}
		targets = append(targets, auditTarget{
			root:           abs,
			pathsToExtract: lockfiles,
		})
	}
	return targets, nil
}

func isHomeRoot(path string) bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	return filepath.Clean(path) == filepath.Clean(home)
}

func discoverLockfilesHome(home string, onProgress func(found int, currentPath string)) ([]string, error) {
	entries, err := os.ReadDir(home)
	if err != nil {
		locks, err := discoverLockfiles(home, onProgress)
		if err != nil {
			return nil, err
		}
		return dedupePaths(locks), nil
	}

	var (
		mu   sync.Mutex
		seen = make(map[string]struct{})
		wg   sync.WaitGroup
		sem  = make(chan struct{}, homeWalkWorkers)
	)

	addPaths := func(paths []string) {
		if len(paths) == 0 {
			return
		}
		mu.Lock()
		for _, p := range paths {
			seen[p] = struct{}{}
		}
		total := len(seen)
		latest := paths[len(paths)-1]
		mu.Unlock()
		if onProgress != nil {
			onProgress(total, latest)
		}
	}

	if rootLocks, err := discoverHomeRootLockfiles(home); err == nil {
		addPaths(rootLocks)
	}

	walkRoot := func(root string) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		locks, err := discoverLockfiles(root, nil)
		if err != nil || len(locks) == 0 {
			return
		}
		addPaths(locks)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, skip := homeTopLevelSkip[entry.Name()]; skip {
			continue
		}
		if shouldSkipDir(entry.Name()) {
			continue
		}
		wg.Add(1)
		go walkRoot(filepath.Join(home, entry.Name()))
	}
	wg.Wait()
	return mapKeysSorted(seen), nil
}

func discoverHomeRootLockfiles(home string) ([]string, error) {
	entries, err := os.ReadDir(home)
	if err != nil {
		return nil, err
	}
	found := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || !lockfile.IsRootName(entry.Name()) {
			continue
		}
		path := filepath.Join(home, entry.Name())
		if _, err := os.Stat(path); err != nil {
			continue
		}
		found = append(found, path)
	}
	return found, nil
}

func dedupePaths(paths []string) []string {
	if len(paths) == 0 {
		return paths
	}
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		seen[p] = struct{}{}
	}
	return mapKeysSorted(seen)
}

func mapKeysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func discoverLockfiles(root string, onProgress func(found int, currentPath string)) ([]string, error) {
	found, err := discoverLockfilesUnix(root)
	if err == nil {
		if onProgress != nil && len(found) > 0 {
			onProgress(len(found), found[len(found)-1])
		}
		return found, nil
	}
	return discoverLockfilesWalk(root, onProgress)
}

func discoverLockfilesWalk(root string, onProgress func(found int, currentPath string)) ([]string, error) {
	var found []string
	dirsVisited := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			dirsVisited++
			if onProgress != nil && (dirsVisited == 1 || dirsVisited%500 == 0) {
				onProgress(len(found), path)
			}
			if path != root && shouldSkipDirPath(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isLockfilePath(path) {
			return nil
		}
		found = append(found, path)
		if onProgress != nil {
			onProgress(len(found), path)
		}
		return nil
	})
	return found, err
}
