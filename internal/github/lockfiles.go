package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
)

type contentEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"`
	DownloadURL string `json:"download_url"`
	Content     string `json:"content"`
	Encoding    string `json:"encoding"`
}

// ResolveSources returns local scan paths for a repo: SBOM when available,
// otherwise lockfiles discovered in the repository tree.
func (c *Client) ResolveSources(ctx context.Context, repo Repo, opts FetchOptions) ([]string, error) {
	sbomPath, err := c.FetchSBOM(ctx, repo, opts)
	if err == nil {
		return []string{sbomPath}, nil
	}
	if !isNotFound(err) {
		return nil, err
	}

	status(opts, fmt.Sprintf("SBOM unavailable for %s, fetching lockfiles…", repo))
	paths, lfErr := c.FetchLockfiles(ctx, repo, opts)
	if lfErr != nil {
		return nil, fmt.Errorf("%w; lockfiles: %v", err, lfErr)
	}
	if len(paths) == 0 {
		return nil, noDependencySourcesError(repo, err, lfErr)
	}
	return paths, nil
}

func noDependencySourcesError(repo Repo, sbomErr, lockfileErr error) error {
	if lockfileErr != nil {
		if apiErr, ok := AsAPIError(lockfileErr); ok && apiErr.NotFound() {
			return fmt.Errorf("%s: repository not found", repo)
		}
		if apiErr, ok := AsAPIError(lockfileErr); ok && apiErr.StatusCode == http.StatusForbidden {
			return fmt.Errorf("%s: access denied (set DEPX_GITHUB_TOKEN or GITHUB_TOKEN for private repos)", repo)
		}
	}
	if isNotFound(sbomErr) && isNotFound(lockfileErr) {
		return fmt.Errorf("%s: repository not found", repo)
	}
	return fmt.Errorf("%s: no dependency SBOM or lockfiles found", repo)
}

func (c *Client) FetchLockfiles(ctx context.Context, repo Repo, opts FetchOptions) ([]string, error) {
	if opts.CacheDir == "" {
		return nil, fmt.Errorf("github cache directory is required")
	}

	repoPaths, err := c.discoverLockfilePaths(ctx, repo)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(repoPaths))
	for _, repoPath := range repoPaths {
		cachePath, err := c.fetchLockfilePath(ctx, repo, opts, repoPath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", repoPath, err)
		}
		out = append(out, cachePath)
	}
	return out, nil
}

func (c *Client) fetchLockfilePath(ctx context.Context, repo Repo, opts FetchOptions, repoPath string) (string, error) {
	cachePath := c.lockfileCachePath(opts.CacheDir, repo, repoPath)
	if body, ok := readFreshCache(cachePath, c.CacheTTL); ok && len(body) > 0 {
		status(opts, fmt.Sprintf("Using cached %s for %s", repoPath, repo))
		return cachePath, nil
	}

	entry, err := c.fetchContentEntry(ctx, repo, repoPath)
	if err != nil {
		return "", err
	}
	raw, err := c.downloadContent(ctx, entry)
	if err != nil {
		return "", err
	}
	if err := writeCache(cachePath, raw); err != nil {
		return "", err
	}
	return cachePath, nil
}

func (c *Client) fetchContentEntry(ctx context.Context, repo Repo, repoPath string) (contentEntry, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.APIBase, repo.Owner, repo.Name, encodeRepoPath(repoPath))
	body, statusCode, hdr, err := c.doRequestWithHeaders(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return contentEntry{}, err
	}
	if statusCode == http.StatusNotFound {
		return contentEntry{}, newAPIError(endpoint, statusCode, body, hdr)
	}
	if statusCode != http.StatusOK {
		return contentEntry{}, newAPIError(endpoint, statusCode, body, hdr)
	}
	var entry contentEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		return contentEntry{}, err
	}
	if entry.Path == "" {
		entry.Path = repoPath
	}
	if entry.Name == "" {
		entry.Name = pathBase(repoPath)
	}
	return entry, nil
}

func (c *Client) lockfileCachePath(cacheDir string, repo Repo, repoPath string) string {
	return filepath.Join(strings.TrimRight(cacheDir, "/"), "github", repo.Owner, repo.Name, "lockfiles", filepath.FromSlash(repoPath))
}

func (c *Client) downloadContent(ctx context.Context, entry contentEntry) ([]byte, error) {
	if entry.DownloadURL != "" {
		body, statusCode, err := c.doRequest(ctx, http.MethodGet, entry.DownloadURL, nil)
		if err != nil {
			return nil, err
		}
		if statusCode != http.StatusOK {
			return nil, fmt.Errorf("download %s: status %d", entry.Name, statusCode)
		}
		return body, nil
	}
	if entry.Encoding == "base64" && entry.Content != "" {
		return base64.StdEncoding.DecodeString(strings.ReplaceAll(entry.Content, "\n", ""))
	}
	return nil, fmt.Errorf("no content for %s", entry.Name)
}

func encodeRepoPath(repoPath string) string {
	segments := strings.Split(strings.Trim(repoPath, "/"), "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	return strings.Join(segments, "/")
}

func pathBase(repoPath string) string {
	if i := strings.LastIndex(repoPath, "/"); i >= 0 {
		return repoPath[i+1:]
	}
	return repoPath
}
