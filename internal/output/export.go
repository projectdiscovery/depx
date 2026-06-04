package output

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/depx/internal/audit"
)

var knownExportExts = []string{".json", ".csv", ".txt"}

// ResolveExportPath maps --output and --output-format to a concrete file path.
// When outputFlag is empty a temp file is created.
func ResolveExportPath(outputFlag string, format ExportFormat, formats []ExportFormat) (string, error) {
	outputFlag = strings.TrimSpace(outputFlag)
	if outputFlag != "" {
		if len(formats) == 1 {
			return resolveSingleExportPath(outputFlag, format.ext()), nil
		}
		return stripKnownExportExt(outputFlag) + format.ext(), nil
	}
	return createTempExportPath(format)
}

func resolveSingleExportPath(outputFlag, ext string) string {
	lower := strings.ToLower(outputFlag)
	if strings.HasSuffix(lower, ext) {
		return outputFlag
	}
	if strip := stripKnownExportExt(outputFlag); strip != outputFlag {
		return strip + ext
	}
	return outputFlag + ext
}

func stripKnownExportExt(path string) string {
	lower := strings.ToLower(path)
	for _, ext := range knownExportExts {
		if strings.HasSuffix(lower, ext) {
			return path[:len(path)-len(ext)]
		}
	}
	return path
}

func createTempExportPath(format ExportFormat) (string, error) {
	pattern := "depx-audit-*" + format.ext()
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// WriteAuditExport writes an audit result using the requested export format.
func WriteAuditExport(path string, format ExportFormat, version, command string, result *audit.Result) (string, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	switch format {
	case ExportJSON:
		return WriteResultFile(path, version, command, result)
	case ExportCSV:
		if err := WriteAuditCSV(path, result); err != nil {
			return "", err
		}
		return path, nil
	case ExportTXT:
		if err := WriteAuditTextFile(path, result); err != nil {
			return "", err
		}
		return path, nil
	default:
		return "", fmt.Errorf("unsupported export format %q", format)
	}
}
