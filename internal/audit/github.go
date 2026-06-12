package audit

import (
	"context"
	"fmt"
	"sync"

	"github.com/projectdiscovery/depx/internal/github"
)

// GitHubOptions configures optional GitHub SBOM audit inputs.
type GitHubOptions struct {
	Client   *github.Client
	CacheDir string
}

type githubResolveJob struct {
	input string
	repo  github.Repo
}

func materializeAuditPaths(ctx context.Context, paths []string, gh *GitHubOptions, status func(string)) ([]string, map[string]string, error) {
	if len(paths) == 0 {
		return paths, nil, nil
	}

	out := make([]string, 0, len(paths))
	labels := make(map[string]string)
	jobs := make([]githubResolveJob, 0)

	for _, p := range paths {
		repo, ok := github.ParseRepo(p)
		if !ok {
			out = append(out, p)
			continue
		}
		jobs = append(jobs, githubResolveJob{input: p, repo: repo})
	}

	if len(jobs) > 0 && status != nil {
		status(fmt.Sprintf("Resolving %d GitHub repositories…", len(jobs)))
	}
	if len(jobs) == 0 {
		return out, labels, nil
	}
	if gh == nil || gh.Client == nil {
		return nil, nil, fmt.Errorf("github audit client is not configured")
	}

	skipped, err := resolveGitHubRepos(ctx, gh, jobs, status, func(resolved []string, repo github.Repo) {
		for _, path := range resolved {
			out = append(out, path)
			labels[path] = repo.AuditRef()
		}
	})
	if err != nil {
		return nil, nil, err
	}

	if len(out) == 0 {
		return nil, nil, fmt.Errorf("no auditable repositories (%d skipped)", skipped)
	}
	if skipped > 0 && status != nil {
		status(fmt.Sprintf("Skipped %d repositories", skipped))
	}

	return out, labels, nil
}

func resolveGitHubRepos(ctx context.Context, gh *GitHubOptions, jobs []githubResolveJob, status func(string), add func([]string, github.Repo)) (skipped int, err error) {
	if len(jobs) == 1 {
		return resolveOneGitHubRepo(ctx, gh, jobs[0], status, add)
	}

	var (
		mu       sync.Mutex
		statusMu sync.Mutex
		wg       sync.WaitGroup
	)
	safeStatus := func(msg string) {
		if status == nil {
			return
		}
		statusMu.Lock()
		status(msg)
		statusMu.Unlock()
	}

	work := make(chan githubResolveJob)
	workerCount := github.ParallelWorkers(gh.Client.Token)
	if workerCount > len(jobs) {
		workerCount = len(jobs)
	}

	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for job := range work {
				if ctx.Err() != nil {
					return
				}
				n, resolveErr := resolveOneGitHubRepo(ctx, gh, job, safeStatus, func(paths []string, repo github.Repo) {
					mu.Lock()
					add(paths, repo)
					mu.Unlock()
				})
				if resolveErr == nil {
					continue
				}
				mu.Lock()
				skipped += n
				mu.Unlock()
			}
		}()
	}

	go func() {
		defer close(work)
		for _, job := range jobs {
			select {
			case <-ctx.Done():
				return
			case work <- job:
			}
		}
	}()

	wg.Wait()
	return skipped, ctx.Err()
}

func resolveOneGitHubRepo(ctx context.Context, gh *GitHubOptions, job githubResolveJob, status func(string), add func([]string, github.Repo)) (skipped int, err error) {
	fetchOpts := github.FetchOptions{
		CacheDir: gh.CacheDir,
		OnStatus: status,
	}
	resolved, err := gh.Client.ResolveSources(ctx, job.repo, fetchOpts)
	if err != nil {
		if status != nil {
			status(fmt.Sprintf("Skipping %s (%s)", job.repo, github.RepoSkipReason(err)))
		}
		return 1, err
	}
	add(resolved, job.repo)
	return 0, nil
}

func hasGitHubInput(paths []string) bool {
	for _, p := range paths {
		if github.IsExplicitAuditRef(p) {
			return true
		}
	}
	return false
}

func attachSourceLabels(targets []auditTarget, labels map[string]string) {
	if len(labels) == 0 {
		return
	}
	for i := range targets {
		if targets[i].sourceLabels == nil {
			targets[i].sourceLabels = map[string]string{}
		}
		for _, path := range targets[i].pathsToExtract {
			if label, ok := labels[path]; ok {
				targets[i].sourceLabels[path] = label
			}
		}
	}
}
