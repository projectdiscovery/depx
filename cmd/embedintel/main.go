package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/depx/internal/bundle"
	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/sync"
)

func main() {
	var (
		outDir   string
		minimal  bool
		source   string
		cacheDir string
		timeout  time.Duration
	)
	flag.StringVar(&outDir, "out", "internal/bundle/data", "output directory for *.tar.gz bundles")
	flag.BoolVar(&minimal, "minimal", false, "build tiny stub bundles (no network)")
	flag.StringVar(&source, "source", "all", "osv, pd, or all")
	flag.StringVar(&cacheDir, "cache", "", "pack existing cache dir instead of fetching")
	flag.DurationVar(&timeout, "timeout", config.DefaultTimeout, "fetch timeout for full bundles")
	flag.Parse()

	builtAt := time.Now().UTC().Truncate(time.Second)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fail(err)
	}

	build := func(src string) error {
		out := filepath.Join(outDir, src+".tar.gz")
		if cacheDir != "" {
			return bundle.BuildFromCache(cacheDir, src, out)
		}
		if minimal {
			switch src {
			case "osv":
				return bundle.BuildMinimalOSV(out, builtAt)
			case "pd":
				return bundle.BuildMinimalPD(out, builtAt)
			default:
				return fmt.Errorf("unknown source %q", src)
			}
		}
		tmp, err := os.MkdirTemp("", "depx-embedintel-fetch-"+src+"-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)

		cfg := sync.Config{
			CacheDir:    tmp,
			UserAgent:   "depx-embedintel (+https://github.com/projectdiscovery/depx)",
			Timeout:     timeout,
			Source:      src,
			MinInterval: 0,
		}
		eng := sync.NewEngine(cfg)
		if _, err := eng.LoadIndex(context.Background(), nil, func(msg string) {
			fmt.Fprintf(os.Stderr, "[%s] %s\n", src, msg)
		}); err != nil {
			return fmt.Errorf("%s fetch: %w", src, err)
		}
		return bundle.BuildFromCache(tmp, src, out)
	}

	sources := []string{"osv", "pd"}
	switch source {
	case "all":
	case "osv", "pd":
		sources = []string{source}
	default:
		fail(fmt.Errorf("invalid -source %q", source))
	}

	for _, src := range sources {
		if src == "pd" && !minimal && cacheDir == "" && os.Getenv("DEPX_PD_API_TOKEN") == "" && os.Getenv("DEPX_PD_TOKEN") == "" {
			fail(fmt.Errorf("pd full bundle requires DEPX_PD_API_TOKEN"))
		}
		fmt.Fprintf(os.Stderr, "building %s bundle -> %s\n", src, filepath.Join(outDir, src+".tar.gz"))
		if err := build(src); err != nil {
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "embedintel: %v\n", err)
	os.Exit(1)
}
