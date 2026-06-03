package audit

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ExcludeSet holds package suppressions loaded from an exclude file. Any audited
// dependency that matches an entry is dropped from findings — used to silence
// known false positives. Entries are "ecosystem:name"; an ecosystem of "*"
// matches any ecosystem.
type ExcludeSet struct {
	exact map[string]struct{} // canonicalEcosystem + "\x00" + lower(name)
	any   map[string]struct{} // lower(name) — matches any ecosystem
}

// Empty reports whether the set has no entries.
func (s ExcludeSet) Empty() bool {
	return len(s.exact) == 0 && len(s.any) == 0
}

// Has reports whether the given ecosystem/name pair is excluded.
func (s ExcludeSet) Has(ecosystem, name string) bool {
	if s.Empty() {
		return false
	}
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if _, ok := s.any[n]; ok {
		return true
	}
	_, ok := s.exact[canonicalEcosystem(ecosystem)+"\x00"+n]
	return ok
}

// LoadExcludeFile reads newline-separated "ecosystem:name" entries from path.
// Blank lines and lines beginning with '#' are ignored. An ecosystem of "*"
// matches any ecosystem. The ecosystem/name split is on the first colon, so
// Maven coordinates ("Maven:group:artifact") are preserved. Malformed lines
// return an error citing the line number.
func LoadExcludeFile(path string) (ExcludeSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return ExcludeSet{}, fmt.Errorf("open exclude file: %w", err)
	}
	defer f.Close()

	set := ExcludeSet{
		exact: map[string]struct{}{},
		any:   map[string]struct{}{},
	}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		eco, name, ok := strings.Cut(raw, ":")
		if !ok {
			return ExcludeSet{}, fmt.Errorf("exclude file %s line %d: expected \"ecosystem:name\", got %q", path, lineNo, raw)
		}
		eco = strings.TrimSpace(eco)
		name = strings.ToLower(strings.TrimSpace(name))
		if eco == "" || name == "" {
			return ExcludeSet{}, fmt.Errorf("exclude file %s line %d: empty ecosystem or name in %q", path, lineNo, raw)
		}
		if eco == "*" {
			set.any[name] = struct{}{}
			continue
		}
		set.exact[canonicalEcosystem(eco)+"\x00"+name] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return ExcludeSet{}, fmt.Errorf("read exclude file %s: %w", path, err)
	}
	return set, nil
}

// canonicalEcosystem maps ecosystem synonyms to a lowercase canonical token so
// exclude entries match dependency ecosystems regardless of source casing
// (e.g. "python" and "PyPI" both match the PyPI ecosystem).
func canonicalEcosystem(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "pypi", "python":
		return "pypi"
	case "go", "golang":
		return "go"
	case "crates", "crates.io", "cargo", "rust":
		return "crates.io"
	case "ruby", "gem", "rubygems":
		return "rubygems"
	case "maven", "java":
		return "maven"
	case "npm", "javascript", "js", "node":
		return "npm"
	default:
		return strings.ToLower(strings.TrimSpace(eco))
	}
}
