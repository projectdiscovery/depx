package config

import "fmt"

func normalizeLimit(limit, fallback, max int) (int, error) {
	if limit < 0 {
		return 0, fmt.Errorf("--limit must be >= 0")
	}
	if limit == 0 {
		limit = fallback
	}
	if limit > max {
		return 0, fmt.Errorf("--limit exceeds maximum of %d", max)
	}
	return limit, nil
}

// NormalizeFeedLimit resolves CLI/config feed limits and rejects invalid values.
func NormalizeFeedLimit(limit, fallback int) (int, error) {
	return normalizeLimit(limit, fallback, MaxFeedLimit)
}

// NormalizeGitHubRepoLimit resolves org/user repo list limits for depx github.
// When the user did not specify a limit, the default depends on authentication:
// unauthenticated scans use a much lower cap to stay within GitHub's ~60 req/hr
// budget. An explicit limit is always honored (up to MaxGitHubRepoLimit).
func NormalizeGitHubRepoLimit(limit int, authenticated bool) (int, error) {
	fallback := DefaultGitHubRepoLimit
	if !authenticated {
		fallback = DefaultGitHubRepoLimitUnauth
	}
	return normalizeLimit(limit, fallback, MaxGitHubRepoLimit)
}
