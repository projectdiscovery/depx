package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/projectdiscovery/depx/internal/lockfile"
)

const maxLockfilesPerRepo = 32

var skipLockfileDirNames = map[string]struct{}{
	".git":         {},
	".hg":          {},
	".svn":         {},
	".next":        {},
	".turbo":       {},
	".cache":       {},
	".pnpm-store":  {},
	".venv":        {},
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

type repoMetadata struct {
	DefaultBranch string `json:"default_branch"`
}

type gitRefResponse struct {
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

type gitTreeResponse struct {
	Tree      []gitTreeEntry `json:"tree"`
	Truncated bool           `json:"truncated"`
}

type gitTreeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func (c *Client) discoverLockfilePaths(ctx context.Context, repo Repo) ([]string, error) {
	paths, err := c.discoverLockfilePathsFromTree(ctx, repo)
	if err == nil {
		return paths, nil
	}
	return c.discoverLockfilePathsFromRoot(ctx, repo)
}

func (c *Client) discoverLockfilePathsFromTree(ctx context.Context, repo Repo) ([]string, error) {
	branch, err := c.repoDefaultBranch(ctx, repo)
	if err != nil {
		return nil, err
	}
	treeSHA, err := c.branchTreeSHA(ctx, repo, branch)
	if err != nil {
		return nil, err
	}
	entries, truncated, err := c.recursiveTree(ctx, repo, treeSHA)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0)
	seen := make(map[string]struct{})
	for _, entry := range entries {
		if entry.Type != "blob" {
			continue
		}
		if !lockfile.IsRootName(path.Base(entry.Path)) {
			continue
		}
		if shouldSkipLockfilePath(entry.Path) {
			continue
		}
		if _, ok := seen[entry.Path]; ok {
			continue
		}
		seen[entry.Path] = struct{}{}
		out = append(out, entry.Path)
		if len(out) >= maxLockfilesPerRepo {
			break
		}
	}
	if len(out) >= maxLockfilesPerRepo {
		return out, nil
	}
	_ = truncated
	return out, nil
}

func (c *Client) discoverLockfilePathsFromRoot(ctx context.Context, repo Repo) ([]string, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/contents", c.APIBase, repo.Owner, repo.Name)
	body, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, newAPIError(endpoint, statusCode, body, hdr)
	}

	var entries []contentEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	out := make([]string, 0)
	for _, entry := range entries {
		if entry.Type != "file" {
			continue
		}
		if !lockfile.IsRootName(entry.Name) {
			continue
		}
		repoPath := entry.Path
		if repoPath == "" {
			repoPath = entry.Name
		}
		out = append(out, repoPath)
	}
	return out, nil
}

func (c *Client) repoDefaultBranch(ctx context.Context, repo Repo) (string, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s", c.APIBase, repo.Owner, repo.Name)
	body, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	if statusCode != http.StatusOK {
		return "", newAPIError(endpoint, statusCode, body, hdr)
	}
	var meta repoMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", err
	}
	branch := strings.TrimSpace(meta.DefaultBranch)
	if branch == "" {
		return "", fmt.Errorf("default branch unavailable for %s", repo)
	}
	return branch, nil
}

func (c *Client) branchTreeSHA(ctx context.Context, repo Repo, branch string) (string, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/ref/heads/%s", c.APIBase, repo.Owner, repo.Name, url.PathEscape(branch))
	body, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	if statusCode != http.StatusOK {
		return "", newAPIError(endpoint, statusCode, body, hdr)
	}
	var ref gitRefResponse
	if err := json.Unmarshal(body, &ref); err != nil {
		return "", err
	}
	if ref.Object.SHA == "" {
		return "", fmt.Errorf("branch ref unavailable for %s", repo)
	}
	return ref.Object.SHA, nil
}

func (c *Client) recursiveTree(ctx context.Context, repo Repo, treeSHA string) ([]gitTreeEntry, bool, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", c.APIBase, repo.Owner, repo.Name, treeSHA)
	body, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, err
	}
	if statusCode != http.StatusOK {
		return nil, false, newAPIError(endpoint, statusCode, body, hdr)
	}
	var tree gitTreeResponse
	if err := json.Unmarshal(body, &tree); err != nil {
		return nil, false, err
	}
	return tree.Tree, tree.Truncated, nil
}

func shouldSkipLockfilePath(repoPath string) bool {
	repoPath = strings.Trim(repoPath, "/")
	if repoPath == "" {
		return true
	}
	for _, seg := range strings.Split(repoPath, "/") {
		if _, skip := skipLockfileDirNames[strings.ToLower(seg)]; skip {
			return true
		}
	}
	return false
}
