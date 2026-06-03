package audit

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// writeSBOM serializes the audited dependencies to an SBOM file and returns the
// absolute path that was written. CycloneDX is the default; SPDX is also
// supported. Format is resolved from the explicit flag, then the file name, then
// the default.
func writeSBOM(path, formatFlag, toolVersion string, deps []Dependency) (string, error) {
	format, err := resolveSBOMFormat(formatFlag, path)
	if err != nil {
		return "", err
	}

	var data []byte
	switch format {
	case "spdx":
		data, err = buildSPDX(toolVersion, deps)
	default:
		data, err = buildCycloneDX(toolVersion, deps)
	}
	if err != nil {
		return "", err
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if dir := filepath.Dir(abs); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(abs, data, 0o644); err != nil {
		return "", err
	}
	return abs, nil
}

func resolveSBOMFormat(flag, path string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(flag)) {
	case "cyclonedx", "cdx":
		return "cyclonedx", nil
	case "spdx":
		return "spdx", nil
	case "":
		if strings.Contains(strings.ToLower(path), "spdx") {
			return "spdx", nil
		}
		return "cyclonedx", nil
	default:
		return "", fmt.Errorf("unsupported sbom format %q (use cyclonedx or spdx)", flag)
	}
}

func buildCycloneDX(toolVersion string, deps []Dependency) ([]byte, error) {
	type component struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		PURL    string `json:"purl,omitempty"`
	}
	components := make([]component, 0, len(deps))
	for _, d := range deps {
		components = append(components, component{
			Type:    "library",
			Name:    d.Name,
			Version: d.Version,
			PURL:    purlFor(d.Ecosystem, d.Name, d.Version),
		})
	}
	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:" + randUUID(),
		"version":      1,
		"metadata": map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]string{{
				"vendor":  "ProjectDiscovery",
				"name":    "depx",
				"version": sbomToolVersion(toolVersion),
			}},
		},
		"components": components,
	}
	return json.MarshalIndent(doc, "", "  ")
}

func buildSPDX(toolVersion string, deps []Dependency) ([]byte, error) {
	type extRef struct {
		ReferenceCategory string `json:"referenceCategory"`
		ReferenceType     string `json:"referenceType"`
		ReferenceLocator  string `json:"referenceLocator"`
	}
	type spdxPackage struct {
		Name             string   `json:"name"`
		SPDXID           string   `json:"SPDXID"`
		VersionInfo      string   `json:"versionInfo,omitempty"`
		DownloadLocation string   `json:"downloadLocation"`
		FilesAnalyzed    bool     `json:"filesAnalyzed"`
		ExternalRefs     []extRef `json:"externalRefs,omitempty"`
	}
	packages := make([]spdxPackage, 0, len(deps))
	for i, d := range deps {
		p := spdxPackage{
			Name:             d.Name,
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			VersionInfo:      d.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		}
		if purl := purlFor(d.Ecosystem, d.Name, d.Version); purl != "" {
			p.ExternalRefs = []extRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			}}
		}
		packages = append(packages, p)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	doc := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "depx-audit",
		"documentNamespace": "https://projectdiscovery.io/depx/" + randUUID(),
		"creationInfo": map[string]any{
			"created":  now,
			"creators": []string{"Tool: depx-" + sbomToolVersion(toolVersion)},
		},
		"packages": packages,
	}
	return json.MarshalIndent(doc, "", "  ")
}

func sbomToolVersion(v string) string {
	if strings.TrimSpace(v) == "" {
		return "dev"
	}
	return v
}

// purlFor builds a best-effort Package URL for a dependency. Returns "" when the
// ecosystem or name is unknown.
func purlFor(ecosystem, name, version string) string {
	typ := purlType(ecosystem)
	if typ == "" || name == "" {
		return ""
	}
	var purl string
	if typ == "maven" && strings.Contains(name, ":") {
		parts := strings.SplitN(name, ":", 2)
		purl = "pkg:maven/" + parts[0] + "/" + parts[1]
	} else {
		purl = "pkg:" + typ + "/" + name
	}
	if version != "" {
		purl += "@" + version
	}
	return purl
}

func purlType(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm", "javascript", "js":
		return "npm"
	case "pypi", "python":
		return "pypi"
	case "go", "golang":
		return "golang"
	case "crates.io", "crates", "cargo", "rust":
		return "cargo"
	case "rubygems", "ruby", "gem":
		return "gem"
	case "maven", "java":
		return "maven"
	case "":
		return ""
	default:
		return strings.ToLower(ecosystem)
	}
}

func randUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%016x%016x", time.Now().UnixNano(), time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
