package github

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Repo identifies a GitHub repository for dependency graph SBOM export.
type Repo struct {
	Owner string
	Name  string
}

func (r Repo) String() string {
	return r.Owner + "/" + r.Name
}

func (r Repo) URL() string {
	return "https://github.com/" + r.String()
}

// DisplayTarget returns a schema-less GitHub label for results output.
func (r Repo) DisplayTarget() string {
	return "github.com/" + r.String()
}

// AuditRef returns the canonical depx internal label for this repository.
func (r Repo) AuditRef() string {
	return "github:" + r.String()
}

// DisplayTarget returns a user-facing label for an audit path.
func DisplayTarget(path string) string {
	for _, prefix := range []string{"github:", "gh:"} {
		if rest, ok := strings.CutPrefix(path, prefix); ok {
			return "github.com/" + rest
		}
	}
	path = strings.TrimPrefix(path, "https://")
	path = strings.TrimPrefix(path, "http://")
	path = strings.TrimPrefix(path, "www.")
	if strings.HasPrefix(path, "github.com/") {
		return strings.TrimSuffix(path, ".git")
	}
	return path
}

// DisplayTargets returns user-facing labels for github subcommand inputs.
func DisplayTargets(inputs []string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("github target is required")
	}
	out := make([]string, 0, len(inputs))
	for _, input := range inputs {
		target, err := ParseTarget(input)
		if err != nil {
			return nil, err
		}
		if target.IsOrg() {
			out = append(out, "github.com/"+target.Owner)
			continue
		}
		if repo, ok := target.Repo(); ok {
			out = append(out, repo.DisplayTarget())
		}
	}
	return out, nil
}

// DisplayOwners returns sorted github.com/owner labels for unique repository owners.
func DisplayOwners(repos []Repo) []string {
	if len(repos) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(repos))
	for _, repo := range repos {
		if repo.Owner == "" {
			continue
		}
		seen[repo.Owner] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for owner := range seen {
		out = append(out, "github.com/"+owner)
	}
	sort.Strings(out)
	return out
}

func (r Repo) CachePath(cacheDir string) string {
	return fmt.Sprintf("%s/github/%s/%s/sbom.spdx.json", strings.TrimRight(cacheDir, "/"), r.Owner, r.Name)
}

// Target is a GitHub repository or an org/user to expand into repositories.
type Target struct {
	Owner string
	Name  string // empty when scanning all repos for Owner
}

func (t Target) IsOrg() bool {
	return t.Name == ""
}

func (t Target) Repo() (Repo, bool) {
	if t.IsOrg() {
		return Repo{}, false
	}
	return Repo{Owner: t.Owner, Name: t.Name}, true
}

// ParseTarget parses github subcommand inputs:
//   - https://github.com/owner/repo(.git)
//   - https://github.com/owner (org or user — lists repositories)
//   - github.com/owner/repo
//   - github:owner/repo / gh:owner/repo
//   - owner/repo
//   - owner (org or user — lists repositories)
func ParseTarget(input string) (Target, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return Target{}, fmt.Errorf("github target is required")
	}
	if looksLikeFilesystemPath(input) {
		return Target{}, fmt.Errorf("invalid github target %q", input)
	}

	for _, prefix := range []string{"github:", "gh:"} {
		if rest, ok := strings.CutPrefix(input, prefix); ok {
			if target, ok := parsePathTarget(rest); ok {
				return target, nil
			}
			return Target{}, fmt.Errorf("invalid github target %q", input)
		}
	}

	if target, ok := parseGitHubURL(input); ok {
		return target, nil
	}
	if repo, ok := parseOwnerRepo(input); ok {
		return Target{Owner: repo.Owner, Name: repo.Name}, nil
	}
	if owner, ok := parseOwnerOnly(input); ok {
		return Target{Owner: owner}, nil
	}
	return Target{}, fmt.Errorf("invalid github target %q", input)
}

func parseGitHubURL(input string) (Target, bool) {
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err != nil || !isGitHubHost(u.Host) {
			return Target{}, false
		}
		return parsePathTarget(strings.Trim(u.Path, "/"))
	}
	if strings.HasPrefix(strings.ToLower(input), "github.com/") {
		return parsePathTarget(input[len("github.com/"):])
	}
	if strings.HasPrefix(strings.ToLower(input), "www.github.com/") {
		return parsePathTarget(input[len("www.github.com/"):])
	}
	return Target{}, false
}

func parsePathTarget(path string) (Target, bool) {
	path = strings.Trim(path, "/")
	if path == "" {
		return Target{}, false
	}
	if repo, ok := parseOwnerRepo(path); ok {
		return Target{Owner: repo.Owner, Name: repo.Name}, true
	}
	parts := strings.Split(path, "/")
	if len(parts) != 1 {
		return Target{}, false
	}
	owner := parts[0]
	if !isValidOwner(owner) {
		return Target{}, false
	}
	return Target{Owner: owner}, true
}

func parseOwnerOnly(input string) (string, bool) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", false
	}
	if strings.ContainsAny(input, "/: \t") || strings.Contains(input, "://") {
		return "", false
	}
	if !isValidOwner(input) {
		return "", false
	}
	return input, true
}

// ParseRepo parses a single repository reference. Returns false for org-only targets.
func ParseRepo(input string) (Repo, bool) {
	target, err := ParseTarget(input)
	if err != nil {
		return Repo{}, false
	}
	return target.Repo()
}

// IsAuditRef reports whether input resolves to a single repository (not org-wide).
func IsAuditRef(input string) bool {
	_, ok := ParseRepo(input)
	return ok
}

// IsExplicitAuditRef reports whether input is an explicit GitHub repository reference
// (github:/gh: prefix or github.com URL), not a bare owner/repo slug that could
// be mistaken for a local path.
func IsExplicitAuditRef(input string) bool {
	input = strings.TrimSpace(input)
	if input == "" {
		return false
	}
	for _, prefix := range []string{"github:", "gh:"} {
		if strings.HasPrefix(input, prefix) {
			_, ok := ParseRepo(input)
			return ok
		}
	}
	if target, ok := parseGitHubURL(input); ok {
		_, ok := target.Repo()
		return ok
	}
	return false
}

func isGitHubHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "github.com" || host == "www.github.com"
}

func parseOwnerRepo(rest string) (Repo, bool) {
	rest = strings.Trim(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Repo{}, false
	}
	owner := parts[0]
	name := parts[1]
	if strings.HasSuffix(strings.ToLower(name), ".git") {
		name = name[:len(name)-4]
	}
	if !isValidOwner(owner) || !isValidRepoName(name) {
		return Repo{}, false
	}
	return Repo{Owner: owner, Name: name}, true
}

func isValidOwner(s string) bool {
	if s == "" || len(s) > 39 {
		return false
	}
	if strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func isValidRepoName(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func looksLikeFilesystemPath(input string) bool {
	if strings.HasPrefix(input, "~") {
		return true
	}
	if filepath.IsAbs(input) {
		return true
	}
	if strings.HasPrefix(input, "./") || strings.HasPrefix(input, "../") {
		return true
	}
	if strings.Contains(input, `\`) {
		return true
	}
	if strings.Contains(input, "/") {
		if _, err := os.Stat(input); err == nil {
			return true
		}
	}
	return false
}
