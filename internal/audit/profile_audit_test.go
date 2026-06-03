//go:build auditprofile

package audit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/projectdiscovery/depx/internal/config"
	"github.com/projectdiscovery/depx/internal/intel"
)

func TestProfileHomeAudit(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	provider, err := intel.New("profile", config.Default())
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(provider, nil)

	totalStart := time.Now()
	phases := make(map[string]time.Duration)

	start := time.Now()
	targets, err := resolveAuditTargetsWithProgress([]string{home}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jobs := collectExtractJobs(targets)
	phases["discover"] = time.Since(start)

	start = time.Now()
	deps, err := svc.collectDependencies(ctx, jobs, []string{home}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	phases["extract+global"] = time.Since(start)

	start = time.Now()
	index, err := provider.LoadMaliciousIndex(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	phases["load_index"] = time.Since(start)

	start = time.Now()
	malicious := 0
	for _, dep := range deps {
		if len(index.Match(dep.Ecosystem, dep.Name, dep.Version)) > 0 {
			malicious++
		}
	}
	phases["match"] = time.Since(start)
	total := time.Since(totalStart)

	t.Logf("home audit profile (%s)", home)
	t.Logf("  lockfiles found:     %d", len(jobs))
	t.Logf("  unique dependencies: %d", len(deps))
	t.Logf("  malicious hits:    %d", malicious)
	for _, name := range []string{"discover", "extract+global", "load_index", "match"} {
		d := phases[name]
		t.Logf("  %-18s %8.2fs  (%5.1f%%)", name+":", d.Seconds(), 100*float64(d)/float64(total))
	}
	t.Logf("  total:              %8.2fs", total.Seconds())
}

func TestProfileHomeDiscoveryBreakdown(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}

	type row struct {
		name string
		d    time.Duration
		n    int
	}
	var rows []row

	start := time.Now()
	locks, err := discoverLockfiles(home, nil)
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, row{"~ (home root)", time.Since(start), len(locks)})

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
		root := home + string(os.PathSeparator) + entry.Name()
		start = time.Now()
		locks, err := discoverLockfiles(root, nil)
		if err != nil {
			t.Logf("  skip %s: %v", entry.Name(), err)
			continue
		}
		if len(locks) == 0 {
			continue
		}
		rows = append(rows, row{entry.Name(), time.Since(start), len(locks)})
	}

	var total time.Duration
	for _, r := range rows {
		total += r.d
	}
	t.Log("home discovery breakdown (sequential find/walk per top-level dir):")
	for _, r := range rows {
		pct := 0.0
		if total > 0 {
			pct = 100 * float64(r.d) / float64(total)
		}
		t.Logf("  %-20s %8.2fs  %4d lockfiles  (%5.1f%%)", r.name+":", r.d.Seconds(), r.n, pct)
	}
	t.Logf("  total sequential:   %8.2fs", total.Seconds())
}
