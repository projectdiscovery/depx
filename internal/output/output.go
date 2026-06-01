package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/depx/internal/audit"
	"github.com/projectdiscovery/depx/internal/check"
	"github.com/projectdiscovery/depx/internal/feed"
	"github.com/projectdiscovery/depx/internal/osv"
	"github.com/projectdiscovery/depx/internal/search"
)

type Options struct {
	JSON    bool
	NoColor bool
	Writer  io.Writer
	ErrOut  io.Writer
}

func NewOptions(json, noColor bool) Options {
	w := io.Writer(os.Stdout)
	e := io.Writer(os.Stderr)
	if noColor || os.Getenv("NO_COLOR") != "" {
		noColor = true
	}
	return Options{JSON: json, NoColor: noColor, Writer: w, ErrOut: e}
}

func (o Options) color() aurora.Aurora {
	if o.NoColor {
		return aurora.NewAurora(false)
	}
	return aurora.NewAurora(true)
}

type Envelope struct {
	SchemaVersion string      `json:"schema_version"`
	Command       string      `json:"command"`
	DepxVersion   string      `json:"depx_version"`
	Data          interface{} `json:"data"`
}

func WriteJSON(w io.Writer, version, command string, data interface{}) error {
	env := Envelope{
		SchemaVersion: "1",
		Command:       command,
		DepxVersion:   version,
		Data:          data,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

func WriteErrorJSON(w io.Writer, version string, code int, message string) error {
	return WriteJSON(w, version, "error", map[string]interface{}{
		"error":   true,
		"code":    code,
		"message": message,
	})
}

func RenderFeed(o Options, version string, result *feed.Result) error {
	if o.JSON {
		return WriteJSON(o.Writer, version, "feed", result)
	}
	c := o.color()
	suffix := fmt.Sprintf("(last %s)", result.Since)
	if result.Ecosystem != "" {
		suffix = fmt.Sprintf("(last %s, ecosystem: %s)", result.Since, result.Ecosystem)
	}

	for i, pkg := range result.Packages {
		if i > 0 {
			writeCardSeparator(o.Writer, c)
		}
		writeFeedCard(o, pkg)
	}
	writeCardFooter(o.Writer, c, len(result.Packages), result.Total, suffix)
	return nil
}

func RenderChecks(o Options, version string, results []check.Result) error {
	if o.JSON {
		return WriteJSON(o.Writer, version, "check", check.BatchResult{
			Total:   len(results),
			Results: results,
		})
	}
	if len(results) == 1 {
		writeCheckCard(o, results[0])
		fmt.Fprintln(o.Writer)
		return nil
	}
	c := o.color()
	for i, result := range results {
		if i > 0 {
			writeCardSeparator(o.Writer, c)
		}
		writeCheckCard(o, result)
	}
	writeCardFooter(o.Writer, c, len(results), len(results), "")
	return nil
}

func RenderIDs(o Options, version string, vulns []*osv.Vulnerability) error {
	if o.JSON {
		return WriteJSON(o.Writer, version, "id", map[string]interface{}{
			"total":   len(vulns),
			"records": vulns,
		})
	}
	if len(vulns) == 1 {
		writeIDCard(o, vulns[0])
		fmt.Fprintln(o.Writer)
		return nil
	}
	c := o.color()
	for i, vuln := range vulns {
		if i > 0 {
			writeCardSeparator(o.Writer, c)
		}
		writeIDCard(o, vuln)
	}
	writeCardFooter(o.Writer, c, len(vulns), len(vulns), "")
	return nil
}

func RenderAudit(o Options, version string, result *audit.Result) error {
	if o.JSON {
		return WriteJSON(o.Writer, version, "audit", result)
	}
	writeAuditResults(o, result)
	return nil
}

func RenderSearch(o Options, version string, result *search.Result) error {
	if o.JSON {
		return WriteJSON(o.Writer, version, "search", result)
	}
	c := o.color()
	suffix := ""
	if result.Ecosystem != "" {
		suffix = fmt.Sprintf("(ecosystem: %s)", result.Ecosystem)
	}
	for i, pkg := range result.Packages {
		if i > 0 {
			writeCardSeparator(o.Writer, c)
		}
		writeFeedCard(o, pkg)
	}
	writeCardFooter(o.Writer, c, len(result.Packages), result.Total, suffix)
	return nil
}

func formatFeedTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func verdictLabel(c aurora.Aurora, verdict string) string {
	switch verdict {
	case check.VerdictMalicious:
		return c.Red("MALICIOUS").String()
	case check.VerdictSuspicious:
		return c.Yellow("SUSPICIOUS").String()
	case check.VerdictUnknown:
		return c.Yellow("UNKNOWN").String()
	case check.VerdictNotFound:
		return c.Yellow("NOT FOUND").String()
	default:
		return c.Green("CLEAN").String()
	}
}
