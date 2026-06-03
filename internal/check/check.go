package check

import (
	"context"
	"fmt"
	"strings"

	"github.com/projectdiscovery/depx/internal/intel"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/ref"
	"github.com/projectdiscovery/depx/internal/registry"
)

const (
	VerdictClean      = "clean"
	VerdictMalicious  = "malicious"
	VerdictSuspicious = "suspicious"
	VerdictUnknown    = "unknown"
	VerdictNotFound   = "not_found"
)

type Service struct {
	intel    intel.Provider
	registry *registry.Client
}

func NewService(provider intel.Provider, reg *registry.Client) *Service {
	return &Service{intel: provider, registry: reg}
}

type BatchResult struct {
	Total   int      `json:"total"`
	Results []Result `json:"results"`
}

type Result struct {
	Ref               string            `json:"ref"`
	PURL              string            `json:"purl"`
	Verdict           string            `json:"verdict"`
	Confidence        string            `json:"confidence"`
	IDs               []string          `json:"ids"`
	Campaign          string            `json:"campaign,omitempty"`
	PackageEcosystem  string            `json:"package_ecosystem,omitempty"`
	PackageName       string            `json:"package_name,omitempty"`
	PackageVersion    string            `json:"package_version,omitempty"`
	PackageURL        string            `json:"registry_url,omitempty"`
	CheckedEcosystems []string          `json:"checked_ecosystems,omitempty"`
	MatchedEcosystems []string          `json:"matched_ecosystems,omitempty"`
	FoundEcosystems   []string          `json:"found_ecosystems,omitempty"`
	Registry          *registry.Status  `json:"registry,omitempty"`
	Advisories        []AdvisorySummary `json:"advisories,omitempty"`
}

type AdvisorySummary struct {
	ID          string              `json:"id"`
	URL         string              `json:"url"`
	Summary     string              `json:"summary,omitempty"`
	ModifiedAt  string              `json:"modified_at,omitempty"`
	PublishedAt string              `json:"published_at,omitempty"`
	References  []AdvisoryReference `json:"references,omitempty"`
}

type AdvisoryReference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url"`
}

func (s *Service) Check(ctx context.Context, pkg ref.PackageRef) (*Result, error) {
	if registry.IsNPMSecurityVersion(pkg.Ecosystem, pkg.Version) {
		result := &Result{
			Ref:              pkg.String(),
			PURL:             "pkg:" + pkg.Ecosystem + "/" + pkg.Name,
			Confidence:       "high",
			PackageEcosystem: pkg.Ecosystem,
			PackageName:      pkg.Name,
			PackageVersion:   pkg.Version,
			Verdict:          VerdictClean,
		}
		applyPackageURL(result)
		return result, nil
	}

	q := osv.QueryRequest{
		Package: &osv.PackageQuery{
			Name:      pkg.Name,
			Ecosystem: pkg.Ecosystem,
		},
	}
	if pkg.Version != "" {
		q.Version = pkg.Version
	}

	resp, err := s.intel.Query(ctx, q)
	if err != nil {
		return nil, err
	}

	malicious := intel.MaliciousVulns(resp.Vulns)
	result := &Result{
		Ref:              pkg.String(),
		PURL:             "pkg:" + pkg.Ecosystem + "/" + pkg.Name,
		Campaign:         "",
		Confidence:       "high",
		PackageEcosystem: pkg.Ecosystem,
		PackageName:      pkg.Name,
		PackageVersion:   pkg.Version,
	}
	applyPackageURL(result)

	for _, v := range malicious {
		result.IDs = append(result.IDs, v.ID)
	}
	result.Advisories = s.buildAdvisoriesFromIDs(ctx, result.IDs)

	switch {
	case len(malicious) > 0:
		if s.shouldSkipPlaceholderMatch(ctx, pkg.Ecosystem, pkg.Name, pkg.Version) {
			result.Verdict = VerdictClean
			result.IDs = nil
			result.Advisories = nil
		} else {
			result.Verdict = VerdictMalicious
		}
	case pkg.Name == "":
		result.Verdict = VerdictUnknown
		result.Confidence = "low"
	default:
		result.Verdict = VerdictClean
	}

	if s.registry != nil && pkg.Name != "" {
		status, err := s.registry.Status(ctx, pkg)
		if err == nil && status != nil {
			result.Registry = status
			switch {
			case status.Status == "not_found" && len(malicious) == 0:
				result.Verdict = VerdictNotFound
				result.Confidence = "high"
			case result.Verdict == VerdictClean && status.Yanked:
				result.Verdict = VerdictSuspicious
				result.Confidence = "medium"
			}
		}
	}

	return result, nil
}

type BareRef struct {
	Name    string
	Version string
}

func (s *Service) CheckAllMany(ctx context.Context, items []BareRef) ([]Result, error) {
	if len(items) == 0 {
		return nil, nil
	}
	ecosystems := ref.CheckEcosystems
	queries := make([]osv.QueryRequest, 0, len(items)*len(ecosystems))
	type querySlot struct {
		item int
		eco  string
	}
	slots := make([]querySlot, 0, len(items)*len(ecosystems))

	for i, item := range items {
		if item.Version != "" && registry.IsNPMSecurityVersion("npm", item.Version) {
			continue
		}
		for _, eco := range ecosystems {
			q := osv.QueryRequest{
				Package: &osv.PackageQuery{
					Name:      item.Name,
					Ecosystem: eco,
				},
			}
			if item.Version != "" {
				q.Version = item.Version
			}
			queries = append(queries, q)
			slots = append(slots, querySlot{item: i, eco: eco})
		}
	}

	batch, err := s.intel.QueryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	results := make([]Result, len(items))
	for i, item := range items {
		results[i] = newBareResult(item.Name, item.Version, ecosystems)
	}

	for qi, slot := range slots {
		if qi >= len(batch.Results) {
			break
		}
		applyQueryHits(&results[slot.item], slot.eco, batch.Results[qi].Vulns)
	}

	for i, item := range items {
		if item.Version != "" && registry.IsNPMSecurityVersion("npm", item.Version) {
			results[i] = newBareResult(item.Name, item.Version, ecosystems)
			results[i].Verdict = VerdictClean
			results[i].PackageEcosystem = "npm"
			results[i].PackageVersion = item.Version
			applyPackageURL(&results[i])
			continue
		}
		finalizeBareResult(&results[i], item.Name, item.Version)
		if results[i].Verdict == VerdictMalicious && s.shouldSkipPlaceholderMatch(ctx, "npm", item.Name, item.Version) {
			results[i].Verdict = VerdictClean
			results[i].IDs = nil
			results[i].MatchedEcosystems = nil
			results[i].Advisories = nil
			continue
		}
		results[i].Advisories = s.buildAdvisoriesFromIDs(ctx, results[i].IDs)
	}

	registryHits := make(map[nameVersionKey][]string)
	if s.registry != nil {
		for i := range results {
			if items[i].Version != "" && registry.IsNPMSecurityVersion("npm", items[i].Version) {
				continue
			}
			if results[i].Verdict != VerdictClean {
				continue
			}
			key := nameVersionKey{name: items[i].Name, version: items[i].Version}
			found, ok := registryHits[key]
			if !ok {
				found = s.registry.FindInEcosystems(ctx, key.name, key.version, ecosystems)
				registryHits[key] = found
			}
			applyFoundEcosystems(&results[i], found)
		}
	}
	return results, nil
}

type nameVersionKey struct {
	name    string
	version string
}

func applyFoundEcosystems(result *Result, found []string) {
	if result == nil {
		return
	}
	if len(found) == 0 {
		result.Verdict = VerdictNotFound
		result.Confidence = "high"
		return
	}
	result.FoundEcosystems = found
}

func (s *Service) CheckAll(ctx context.Context, name, version string) (*Result, error) {
	results, err := s.CheckAllMany(ctx, []BareRef{{Name: name, Version: version}})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return &Result{Verdict: VerdictUnknown, Confidence: "low"}, nil
	}
	return &results[0], nil
}

func newBareResult(name, version string, ecosystems []string) Result {
	r := Result{
		Ref:               bareRefLabel(name, version),
		Campaign:          "",
		Confidence:        "high",
		PackageName:       name,
		PackageVersion:    version,
		CheckedEcosystems: append([]string(nil), ecosystems...),
	}
	return r
}

func applyQueryHits(result *Result, eco string, vulns []osv.Vulnerability) {
	malicious := intel.MaliciousVulns(vulns)
	if len(malicious) == 0 {
		return
	}
	result.MatchedEcosystems = append(result.MatchedEcosystems, eco)
	seen := make(map[string]struct{}, len(result.IDs))
	for _, id := range result.IDs {
		seen[id] = struct{}{}
	}
	for _, v := range malicious {
		if _, ok := seen[v.ID]; ok {
			continue
		}
		seen[v.ID] = struct{}{}
		result.IDs = append(result.IDs, v.ID)
	}
}

func finalizeBareResult(result *Result, name, version string) {
	switch len(result.MatchedEcosystems) {
	case 0:
		result.Verdict = VerdictClean
	case 1:
		result.Verdict = VerdictMalicious
		result.Ref = fmt.Sprintf("%s:%s", strings.ToLower(result.MatchedEcosystems[0]), bareRefLabel(name, version))
		result.PURL = "pkg:" + result.MatchedEcosystems[0] + "/" + name
		result.PackageEcosystem = result.MatchedEcosystems[0]
		if version != "" {
			result.PURL += "@" + version
		}
		applyPackageURL(result)
	default:
		result.Verdict = VerdictMalicious
		applyPackageURL(result)
	}
}

func applyPackageURL(result *Result) {
	if result == nil || result.PackageName == "" {
		return
	}
	eco := result.PackageEcosystem
	if eco == "" && len(result.MatchedEcosystems) == 1 {
		eco = result.MatchedEcosystems[0]
	}
	if eco == "" {
		return
	}
	result.PackageURL = registry.PackagePageURL(eco, result.PackageName)
	if result.PackageEcosystem == "" {
		result.PackageEcosystem = eco
	}
}

func (s *Service) shouldSkipPlaceholderMatch(ctx context.Context, ecosystem, name, version string) bool {
	if registry.IsNPMSecurityVersion(ecosystem, version) {
		return true
	}
	if s.registry == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "javascript", "js":
	default:
		return false
	}
	holding, err := s.registry.IsNPMSecurityHolding(ctx, name)
	return err == nil && holding
}

func bareRefLabel(name, version string) string {
	if version != "" {
		return name + "@" + version
	}
	return name
}

func (s *Service) buildAdvisoriesFromIDs(ctx context.Context, ids []string) []AdvisorySummary {
	out := make([]AdvisorySummary, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.advisorySummary(ctx, osv.Vulnerability{ID: id}))
	}
	return out
}

func (s *Service) advisorySummary(ctx context.Context, stub osv.Vulnerability) AdvisorySummary {
	v := stub
	if full, err := s.intel.GetVuln(ctx, stub.ID); err == nil {
		v = *full
	}
	refs := make([]AdvisoryReference, 0, len(v.References))
	for _, ref := range v.References {
		if ref.URL == "" {
			continue
		}
		refs = append(refs, AdvisoryReference{Type: ref.Type, URL: ref.URL})
	}
	return AdvisorySummary{
		ID:          v.ID,
		URL:         s.intel.VulnPageURL(v.ID),
		Summary:     v.Summary,
		ModifiedAt:  v.Modified,
		PublishedAt: v.Published,
		References:  refs,
	}
}
