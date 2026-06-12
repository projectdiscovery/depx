package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	"github.com/projectdiscovery/depx/internal/check"
	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/lockfile"
	"github.com/projectdiscovery/depx/internal/registry"
)

var lockfilePlugins = []string{
	"javascript/packagelockjson",
	"javascript/yarnlock",
	"javascript/pnpmlock",
	"python/poetrylock",
	"python/pipfilelock",
	"go/gomod",
	"rust/cargolock",
	"ruby/gemfilelock",
	"java/pomxml",
	"java/gradlelockfile",
}

type Dependency struct {
	Ecosystem  string
	Name       string
	Version    string
	Source     string
	SourceType SourceType
}

type Finding struct {
	Verdict    string    `json:"verdict"`
	Ecosystem  string    `json:"ecosystem"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	IDs        []string  `json:"ids"`
	Summary    string    `json:"summary,omitempty"`
	Published  time.Time `json:"published_at,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
	Source     string    `json:"source,omitempty"`
	SourceType string    `json:"source_type,omitempty"`
	Lockfile   string    `json:"lockfile,omitempty"`
	ProjectDir string    `json:"project_dir,omitempty"`
	ProjectURL string    `json:"project_url,omitempty"`
	PackageURL string    `json:"registry_url,omitempty"`
}

type Lockfile struct {
	Path         string `json:"path"`
	Type         string `json:"type,omitempty"`
	Ecosystem    string `json:"ecosystem"`
	Dependencies int    `json:"dependencies"`
}

type Result struct {
	Paths            []string   `json:"paths"`
	Lockfiles        []Lockfile `json:"lockfiles"`
	Dependencies     int        `json:"dependencies"`
	Summary          Summary    `json:"summary"`
	Findings         []Finding  `json:"findings"`
	FindingsStreamed bool       `json:"-"`
	Mode             string     `json:"mode,omitempty"`
	DurationMS       int64      `json:"duration_ms,omitempty"`
	SBOMPath         string     `json:"sbom_path,omitempty"`
}

type Summary struct {
	Lockfiles           int `json:"lockfiles"`
	Total               int `json:"total"`
	Malicious           int `json:"malicious"`
	Quarantined         int `json:"quarantined,omitempty"`
	Suspicious          int `json:"suspicious"`
	Clean               int `json:"clean"`
	SkippedPlaceholders int `json:"skipped_placeholders,omitempty"`
}

type Service struct {
	intel    intel.Provider
	registry *registry.Client
	cacheDir string
}

func NewService(provider intel.Provider, reg *registry.Client, cacheDir string) *Service {
	return &Service{intel: provider, registry: reg, cacheDir: cacheDir}
}

func (s *Service) shouldSkipPlaceholderVersion(dep Dependency) bool {
	return registry.IsNPMSecurityVersion(dep.Ecosystem, dep.Version)
}

func (s *Service) isQuarantinedMatch(ctx context.Context, dep Dependency) bool {
	if s.shouldSkipPlaceholderVersion(dep) {
		return true
	}
	if s.registry == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(dep.Ecosystem)) {
	case "npm", "javascript", "js":
	default:
		return false
	}
	holding, err := s.registry.IsNPMSecurityHolding(ctx, dep.Name)
	return err == nil && holding
}

func (s *Service) persistQuarantine(ecosystem, name string) {
	if s.cacheDir == "" {
		return
	}
	_ = registry.SetQuarantined(s.cacheDir, ecosystem, name, true)
}

type Options struct {
	Progress     *Progress
	GitHub       *GitHubOptions
	DisplayPaths []string // optional user-facing targets (e.g. org URL vs expanded repos)

	// Exclude suppresses matched packages from findings (known false
	// positives). Excluded matches are silently counted as clean.
	Exclude ExcludeSet

	// SBOMExport, when set, writes an SBOM of the audited dependencies to this
	// path. SBOMFormat is optional ("cyclonedx" default, or "spdx").
	SBOMExport      string
	SBOMFormat      string
	SBOMToolVersion string
}

const (
	extractWorkers = 10
)

func (s *Service) Audit(ctx context.Context, paths []string) (*Result, error) {
	return s.AuditWithOptions(ctx, paths, Options{})
}

func (s *Service) AuditWithOptions(ctx context.Context, paths []string, opts Options) (*Result, error) {
	started := time.Now()
	displayPaths := append([]string(nil), paths...)
	if len(opts.DisplayPaths) > 0 {
		displayPaths = append([]string(nil), opts.DisplayPaths...)
	}
	inputPaths := paths
	if len(inputPaths) == 0 {
		inputPaths = defaultAuditPaths()
		displayPaths = append([]string(nil), inputPaths...)
	}

	sourceLabels := map[string]string{}
	if hasGitHubInput(inputPaths) {
		if opts.GitHub == nil || opts.GitHub.Client == nil {
			return nil, fmt.Errorf("GitHub repository references require: depx github <target> (use github:owner/repo or a github.com URL)")
		}
		status := func(string) {}
		if opts.Progress != nil {
			status = opts.Progress.status
		}
		resolved, labels, err := materializeAuditPaths(ctx, inputPaths, opts.GitHub, status)
		if err != nil {
			return nil, err
		}
		inputPaths = resolved
		sourceLabels = labels
	}

	targets, err := resolveAuditTargetsWithProgress(inputPaths, opts.Progress)
	if err != nil {
		return nil, err
	}
	attachSourceLabels(targets, sourceLabels)

	jobs := collectExtractJobs(targets)
	if len(jobs) == 0 && !auditIncludesHome(inputPaths) {
		opts.Progress.status("No lockfiles or SBOM files found")
		return &Result{
			Paths:      displayPaths,
			Summary:    Summary{},
			Mode:       auditMode(opts),
			DurationMS: time.Since(started).Milliseconds(),
		}, nil
	}

	if len(jobs) > 0 {
		opts.Progress.status(auditFilesProgressMessage(len(jobs)))
	}

	allDeps, err := s.collectDependencies(ctx, jobs, inputPaths, opts)
	if err != nil {
		return nil, err
	}

	if len(allDeps) == 0 {
		opts.Progress.status("No dependencies found")
		return &Result{
			Paths:      displayPaths,
			Summary:    Summary{Lockfiles: len(jobs)},
			Mode:       auditMode(opts),
			DurationMS: time.Since(started).Milliseconds(),
		}, nil
	}

	sbomPath := ""
	if opts.SBOMExport != "" {
		written, werr := writeSBOM(opts.SBOMExport, opts.SBOMFormat, opts.SBOMToolVersion, allDeps)
		if werr != nil {
			return nil, fmt.Errorf("sbom export: %w", werr)
		}
		sbomPath = written
	}

	findings, maliciousCount, quarantinedCount, cleanCount, skippedPlaceholders, err := s.matchLocally(ctx, allDeps, opts)
	if err != nil {
		return nil, err
	}

	lockfileSummary := summarizeSources(allDeps)
	opts.Progress.complete()

	streamed := opts.Progress != nil && opts.Progress.OnFinding != nil

	return &Result{
		Paths:        displayPaths,
		Lockfiles:    lockfileSummary,
		Dependencies: len(allDeps),
		Summary: Summary{
			Lockfiles:           len(lockfileSummary),
			Total:               len(allDeps),
			Malicious:           maliciousCount,
			Quarantined:         quarantinedCount,
			Suspicious:          0,
			Clean:               cleanCount,
			SkippedPlaceholders: skippedPlaceholders,
		},
		Findings:         findings,
		FindingsStreamed: streamed,
		Mode:             auditMode(opts),
		DurationMS:       time.Since(started).Milliseconds(),
		SBOMPath:         sbomPath,
	}, nil
}

func auditFilesProgressMessage(n int) string {
	if n == 1 {
		return "Checking dependencies in 1 lockfile or SBOM"
	}
	return fmt.Sprintf("Checking dependencies in %d lockfiles and SBOMs", n)
}

func auditMode(_ Options) string {
	return "local"
}

func auditIncludesHome(paths []string) bool {
	home, err := osUserHome()
	if err != nil {
		return false
	}
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if filepath.Clean(abs) == filepath.Clean(home) {
			return true
		}
	}
	return len(paths) == 0
}

func osUserHome() (string, error) {
	return os.UserHomeDir()
}

func (s *Service) collectDependencies(ctx context.Context, jobs []extractJob, inputPaths []string, opts Options) ([]Dependency, error) {
	seen := map[string]struct{}{}
	allDeps := make([]Dependency, 0)

	addDep := func(dep Dependency) {
		key := dep.Ecosystem + "|" + dep.Name + "|" + dep.Version
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		allDeps = append(allDeps, dep)
	}

	if auditIncludesHome(inputPaths) {
		home, _ := osUserHome()
		opts.Progress.status("Checking global installs...")
		for _, dep := range collectGlobalDependencies(home) {
			addDep(dep)
		}
	}

	if len(jobs) == 0 {
		return allDeps, nil
	}

	type extractResult struct {
		index int
		job   extractJob
		deps  []Dependency
		err   error
	}

	results := make([]extractResult, len(jobs))
	sem := make(chan struct{}, extractWorkers)
	var wg sync.WaitGroup
	endScalibr := beginScalibrExtractSession()
	defer endScalibr()

	for i, job := range jobs {
		wg.Add(1)
		go func(i int, job extractJob) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			deps, err := extractFromSource(ctx, job.root, job.path, job.sourceType, job.label)
			results[i] = extractResult{index: i, job: job, deps: deps, err: err}
		}(i, job)
	}
	wg.Wait()

	for i, res := range results {
		if res.err != nil {
			return nil, fmt.Errorf("%s: %w", res.job.path, res.err)
		}
		newCount := 0
		for _, dep := range res.deps {
			before := len(allDeps)
			addDep(dep)
			if len(allDeps) > before {
				newCount++
			}
		}
		opts.Progress.source(i+1, len(jobs), res.job.path, res.job.sourceType, newCount)
	}

	return allDeps, nil
}

func (s *Service) matchLocally(ctx context.Context, deps []Dependency, opts Options) ([]Finding, int, int, int, int, error) {
	opts.Progress.status("Loading malicious package index...")
	index, err := s.intel.LoadMaliciousIndex(ctx, func(loaded, total int) {
		opts.Progress.index(loaded, total)
	}, func(msg string) {
		opts.Progress.status(msg)
	})
	if err != nil {
		return nil, 0, 0, 0, 0, err
	}

	findings := make([]Finding, 0)
	maliciousCount := 0
	quarantinedCount := 0
	cleanCount := 0
	skippedPlaceholders := 0
	total := len(deps)
	advisoryCache := make(advisoryMetaCache)

	for i, dep := range deps {
		if i == 0 || (i+1)%250 == 0 || i+1 == total {
			opts.Progress.query(i+1, total, dep.Source)
		}
		if s.shouldSkipPlaceholderVersion(dep) {
			skippedPlaceholders++
			cleanCount++
			continue
		}
		matches := index.Match(dep.Ecosystem, dep.Name, dep.Version)
		if len(matches) == 0 {
			cleanCount++
			continue
		}
		if opts.Exclude.Has(dep.Ecosystem, dep.Name) {
			cleanCount++
			continue
		}
		quarantined := s.isQuarantinedMatch(ctx, dep)
		ids := make([]string, 0, len(matches))
		summary := ""
		var published, modified time.Time
		for _, m := range matches {
			ids = append(ids, m.ID)
			if summary == "" {
				summary = m.Summary
			}
			if published.IsZero() && !m.Published.IsZero() {
				published = m.Published
			}
			if modified.IsZero() && !m.Modified.IsZero() {
				modified = m.Modified
			}
		}
		verdict := check.VerdictMalicious
		if quarantined {
			verdict = check.VerdictQuarantined
			s.persistQuarantine(dep.Ecosystem, dep.Name)
		}
		finding := enrichFinding(newFinding(dep, ids, summary, published, modified, verdict))
		s.fillFindingEnrichment(ctx, advisoryCache, &finding)
		findings = append(findings, finding)
		if quarantined {
			quarantinedCount++
		} else {
			maliciousCount++
		}
		opts.Progress.finding(finding)
	}
	opts.Progress.query(total, total, "")
	reportSkippedPlaceholders(opts, skippedPlaceholders)

	return findings, maliciousCount, quarantinedCount, cleanCount, skippedPlaceholders, nil
}

func reportSkippedPlaceholders(opts Options, skipped int) {
	if skipped == 0 || opts.Progress == nil {
		return
	}
	label := "dependencies"
	if skipped == 1 {
		label = "dependency"
	}
	opts.Progress.status(fmt.Sprintf("Skipped %d registry placeholder %s (npm security stubs)", skipped, label))
}

func extractFromSource(ctx context.Context, projectRoot, sourcePath string, sourceType SourceType, label string) ([]Dependency, error) {
	plugins, err := pl.FromNames(pluginsForSource(sourceType), nil)
	if err != nil {
		return nil, err
	}
	absSource, err := filepath.Abs(sourcePath)
	if err != nil {
		return nil, err
	}
	extractPath, cleanup, err := prepareScalibrSBOMPath(absSource)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, err
	}
	if extractPath != absSource {
		absRoot = filepath.Dir(extractPath)
	}
	cfg := &scalibr.ScanConfig{
		ScanRoots:      scalibrfs.RealFSScanRoots(absRoot),
		Plugins:        plugins,
		PathsToExtract: []string{extractPath},
		UseGitignore:   false,
	}
	results := scalibr.New().Scan(ctx, cfg)
	if results != nil && results.Status != nil &&
		results.Status.Status != plugin.ScanStatusSucceeded &&
		results.Status.Status != plugin.ScanStatusPartiallySucceeded {
		reason := results.Status.FailureReason
		if reason == "" {
			reason = "scalibr scan failed"
		}
		return nil, fmt.Errorf("%s", reason)
	}
	deps := make([]Dependency, 0, len(results.Inventory.Packages))
	for _, pkg := range results.Inventory.Packages {
		dep := packageToDependency(pkg, sourcePath, sourceType, label)
		if dep.Name == "" || dep.Ecosystem == "" {
			continue
		}
		deps = append(deps, dep)
	}
	return deps, nil
}

func packageToDependency(pkg *extractor.Package, sourcePath string, sourceType SourceType, label string) Dependency {
	display := sourcePath
	if label != "" {
		display = label
	} else if abs, err := filepath.Abs(sourcePath); err == nil {
		display = abs
	}
	return Dependency{
		Ecosystem:  normalizeDepEcosystem(pkg.Ecosystem().String(), pkg.PURLType),
		Name:       packageName(pkg),
		Version:    packageVersion(pkg),
		Source:     display,
		SourceType: sourceType,
	}
}

// packageName returns the registry-qualified package name. Some extractors
// (notably the SPDX/CycloneDX SBOM parsers) populate Package.Name with only the
// PURL name, dropping the namespace — so a scoped npm package like
// "@babel/helper-annotate-as-pure" arrives as the bare "helper-annotate-as-pure",
// which then collides with an unrelated malicious package of that bare name.
// Rebuild the qualified name from the PURL namespace when present.
//
// Only rebuild when the extractor used the bare PURL name (pkg.Name == purl.Name)
// — that is exactly the SBOM case where the namespace was dropped. Lockfile
// extractors already store the fully-qualified name (e.g. "@babel/foo",
// "github.com/foo/bar", "group:artifact"), so leaving those untouched preserves
// their original casing/format instead of re-deriving from the PURL.
func packageName(pkg *extractor.Package) string {
	p := pkg.PURL()
	if p == nil || p.Namespace == "" || pkg.Name != p.Name {
		return pkg.Name
	}
	sep := "/"
	if strings.EqualFold(p.Type, "maven") {
		sep = ":"
	}
	return p.Namespace + sep + p.Name
}

// packageVersion returns the dependency version. The SPDX SBOM extractor leaves
// Package.Version empty and only records the version inside the PURL, so recover
// it from there. Without this, GitHub SBOM audits carry no version, which both
// hides it from output and prevents matching version-specific advisories.
func packageVersion(pkg *extractor.Package) string {
	if pkg.Version != "" {
		return pkg.Version
	}
	if p := pkg.PURL(); p != nil {
		return p.Version
	}
	return ""
}

func newFinding(dep Dependency, ids []string, summary string, published, modified time.Time, verdict string) Finding {
	f := Finding{
		Verdict:    verdict,
		Ecosystem:  dep.Ecosystem,
		Name:       dep.Name,
		Version:    dep.Version,
		IDs:        ids,
		Summary:    summary,
		Published:  published,
		ModifiedAt: modified,
		Source:     dep.Source,
		SourceType: string(dep.SourceType),
	}
	if dep.SourceType == SourceTypeLockfile {
		f.Lockfile = dep.Source
	}
	return f
}

type advisoryMetaCache map[string]advisoryMeta

type advisoryMeta struct {
	Published time.Time
	Modified  time.Time
}

func (s *Service) fillFindingEnrichment(ctx context.Context, cache advisoryMetaCache, f *Finding) {
	if f == nil || len(f.IDs) == 0 {
		return
	}
	if !f.Published.IsZero() && !f.ModifiedAt.IsZero() {
		return
	}
	id := f.IDs[0]
	meta, ok := cache[id]
	if !ok {
		vuln, err := s.intel.GetVuln(ctx, id)
		if err != nil {
			return
		}
		meta = advisoryMeta{
			Published: vuln.PublishedTime(),
			Modified:  vuln.ModifiedTime(),
		}
		cache[id] = meta
	}
	if f.Published.IsZero() {
		f.Published = meta.Published
	}
	if f.ModifiedAt.IsZero() {
		f.ModifiedAt = meta.Modified
	}
}

func summarizeSources(deps []Dependency) []Lockfile {
	type sourceKey struct {
		path string
		typ  SourceType
	}
	counts := map[sourceKey]int{}
	for _, dep := range deps {
		if dep.Source == "" {
			continue
		}
		key := sourceKey{path: dep.Source, typ: dep.SourceType}
		counts[key]++
	}
	out := make([]Lockfile, 0, len(counts))
	for key, count := range counts {
		out = append(out, Lockfile{
			Path:         key.path,
			Type:         string(key.typ),
			Ecosystem:    inferEcoFromPath(key.path, key.typ),
			Dependencies: count,
		})
	}
	return out
}

func inferEcoFromPath(path string, sourceType SourceType) string {
	if sourceType == SourceTypeSBOM {
		return "sbom"
	}
	base := filepath.Base(path)
	if eco := lockfile.Ecosystem(base); eco != "" {
		return eco
	}
	if strings.Contains(path, "(global)") {
		return "npm"
	}
	if strings.Contains(path, "(go mod cache)") {
		return "Go"
	}
	return ""
}

func normalizeDepEcosystem(eco, purlType string) string {
	eco = strings.TrimSpace(eco)
	if eco != "" && !strings.EqualFold(eco, "unknown") {
		switch strings.ToLower(eco) {
		case "pypi", "python":
			return "PyPI"
		case "go", "golang":
			return "Go"
		case "crates", "cargo", "rust", "crates.io":
			return "crates.io"
		case "ruby", "gem", "rubygems":
			return "RubyGems"
		case "maven", "java":
			return "Maven"
		default:
			return eco
		}
	}
	switch strings.ToLower(purlType) {
	case "maven":
		return "Maven"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "golang":
		return "Go"
	case "cargo":
		return "crates.io"
	case "gem":
		return "RubyGems"
	default:
		return eco
	}
}
