package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/depx/internal/audit"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	depxInfoURI  = "https://github.com/projectdiscovery/depx"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// WriteSARIF renders the audit findings as a SARIF 2.1.0 report at path
// (creating parent directories) and returns the written path. The report is
// consumable by GitHub code scanning and other SARIF-aware tools.
func WriteSARIF(path, toolVersion string, result *audit.Result) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("sarif export: empty path")
	}

	rules := make([]sarifRule, 0)
	ruleSeen := map[string]struct{}{}
	results := make([]sarifResult, 0, len(result.Findings))

	for _, f := range result.Findings {
		ruleID := sarifRuleID(f)
		if _, ok := ruleSeen[ruleID]; !ok {
			ruleSeen[ruleID] = struct{}{}
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             "MaliciousPackage",
				ShortDescription: sarifText{Text: sarifRuleDescription(f)},
				HelpURI:          sarifHelpURI(f),
				Properties:       map[string]any{"tags": []string{"security", "supply-chain", "malicious-package"}},
			})
		}
		results = append(results, sarifResult{
			RuleID:              ruleID,
			Level:               sarifLevel(f.Verdict),
			Message:             sarifText{Text: sarifMessage(f)},
			Locations:           sarifLocations(f),
			PartialFingerprints: sarifFingerprints(f),
		})
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "depx",
				Version:        toolVersion,
				InformationURI: depxInfoURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func sarifRuleID(f audit.Finding) string {
	for _, id := range f.IDs {
		if strings.TrimSpace(id) != "" {
			return id
		}
	}
	return "depx/malicious-package"
}

func sarifRuleDescription(f audit.Finding) string {
	if f.Summary != "" {
		return f.Summary
	}
	return fmt.Sprintf("Known %s package", strings.ToLower(verdictWord(f.Verdict)))
}

func sarifMessage(f audit.Finding) string {
	pkg := f.Name
	if f.Version != "" {
		pkg += "@" + f.Version
	}
	msg := fmt.Sprintf("%s package %s", verdictWord(f.Verdict), pkg)
	if f.Ecosystem != "" {
		msg += fmt.Sprintf(" (%s)", f.Ecosystem)
	}
	if len(f.IDs) > 0 {
		msg += " — " + strings.Join(f.IDs, ", ")
	}
	if f.Summary != "" {
		msg += ": " + f.Summary
	}
	return msg
}

func sarifLevel(verdict string) string {
	switch verdict {
	case "malicious":
		return "error"
	case "suspicious":
		return "warning"
	default:
		return "note"
	}
}

func verdictWord(verdict string) string {
	switch verdict {
	case "malicious":
		return "Malicious"
	case "suspicious":
		return "Suspicious"
	default:
		return "Flagged"
	}
}

func sarifLocations(f audit.Finding) []sarifLocation {
	uri := f.Lockfile
	if uri == "" {
		uri = f.Source
	}
	if uri == "" {
		return nil
	}
	return []sarifLocation{{
		PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(uri)},
		},
	}}
}

func sarifHelpURI(f audit.Finding) string {
	for _, id := range f.IDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if strings.HasPrefix(id, "MAL-") || strings.HasPrefix(id, "GHSA-") || strings.HasPrefix(id, "CVE-") {
			return "https://osv.dev/vulnerability/" + id
		}
	}
	return f.ProjectURL
}

func sarifFingerprints(f audit.Finding) map[string]string {
	key := strings.Join([]string{f.Ecosystem, f.Name, f.Version}, "/")
	if strings.Trim(key, "/") == "" {
		return nil
	}
	return map[string]string{"depx/package": key}
}
