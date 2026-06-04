package output

import (
	"fmt"
	"strings"
)

// ExportFormat is a file export encoding for audit/github results.
type ExportFormat string

const (
	ExportJSON ExportFormat = "json"
	ExportCSV  ExportFormat = "csv"
	ExportTXT  ExportFormat = "txt"
)

var exportFormats = map[ExportFormat]struct{}{
	ExportJSON: {},
	ExportCSV:  {},
	ExportTXT:  {},
}

// ParseExportFormats parses a comma-separated export format list. An empty
// string defaults to json.
func ParseExportFormats(raw string) ([]ExportFormat, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []ExportFormat{ExportJSON}, nil
	}
	parts := strings.Split(raw, ",")
	seen := make(map[ExportFormat]struct{}, len(parts))
	out := make([]ExportFormat, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		f := ExportFormat(part)
		if _, ok := exportFormats[f]; !ok {
			return nil, fmt.Errorf("unknown output format %q (supported: json, csv, txt)", part)
		}
		if _, dup := seen[f]; dup {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	if len(out) == 0 {
		return []ExportFormat{ExportJSON}, nil
	}
	return out, nil
}

func (f ExportFormat) ext() string {
	switch f {
	case ExportJSON:
		return ".json"
	case ExportCSV:
		return ".csv"
	case ExportTXT:
		return ".txt"
	default:
		return ""
	}
}

// ExportNoticeLabel is the human label used in terminal path notices.
func (f ExportFormat) ExportNoticeLabel() string {
	switch f {
	case ExportJSON:
		return "JSON result"
	case ExportCSV:
		return "CSV result"
	case ExportTXT:
		return "Text result"
	default:
		return "Export"
	}
}
