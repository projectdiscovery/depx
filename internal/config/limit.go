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
func NormalizeGitHubRepoLimit(limit int) (int, error) {
	return normalizeLimit(limit, DefaultGitHubRepoLimit, MaxGitHubRepoLimit)
}
