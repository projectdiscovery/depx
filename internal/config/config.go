package config

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultSince           = 24 * time.Hour
	DefaultLimit           = 25
	MaxFeedLimit           = 1000
	DefaultGitHubRepoLimit = 100
	// DefaultGitHubRepoLimitUnauth caps org/user scans when no GitHub token is
	// set. Unauthenticated GitHub REST allows only ~60 requests/hour per IP, and
	// each repo costs roughly one SBOM request, so the default cap is kept low to
	// avoid exhausting the budget (and tripping rate-limit backoff) in one run.
	DefaultGitHubRepoLimitUnauth = 10
	MaxGitHubRepoLimit           = 1000
	DefaultTimeout               = 30 * time.Second
	DefaultCacheTTL              = 30 * time.Minute
)

type Config struct {
	DefaultEcosystem string        `yaml:"default_ecosystem"`
	Timeout          time.Duration `yaml:"timeout"`
	CacheDir         string        `yaml:"cache_dir"`
	Feed             FeedConfig    `yaml:"feed"`
	Sources          []string      `yaml:"sources"`
	Output           OutputConfig  `yaml:"output"`
}

type FeedConfig struct {
	Since    time.Duration `yaml:"since"`
	Limit    int           `yaml:"limit"`
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

type OutputConfig struct {
	Color bool `yaml:"color"`
}

func Default() *Config {
	home, _ := os.UserHomeDir()
	cacheDir := filepath.Join(home, ".cache", "depx")
	return &Config{
		DefaultEcosystem: "npm",
		Timeout:          DefaultTimeout,
		CacheDir:         cacheDir,
		Feed: FeedConfig{
			Since:    DefaultSince,
			Limit:    DefaultLimit,
			CacheTTL: DefaultCacheTTL,
		},
		Sources: []string{"pd"},
		Output: OutputConfig{
			Color: true,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = Default().CacheDir
	}
	if cfg.Feed.Since == 0 {
		cfg.Feed.Since = DefaultSince
	}
	if cfg.Feed.Limit == 0 {
		cfg.Feed.Limit = DefaultLimit
	}
	if cfg.Feed.CacheTTL == 0 {
		cfg.Feed.CacheTTL = DefaultCacheTTL
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	return cfg, nil
}

func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "depx", "config.yaml")
}
