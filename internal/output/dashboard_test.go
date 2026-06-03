package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/projectdiscovery/depx/internal/feed"
	"github.com/projectdiscovery/depx/internal/source"
)

func TestWriteFeedDashboard(t *testing.T) {
	var buf bytes.Buffer
	o := Options{Writer: &buf, NoColor: true}
	result := &feed.Result{
		Since:  "24h",
		Limit:  25,
		Total:  3,
		Shown:  2,
		Source: "osv",
		Window: source.WindowStats{
			Advisories:     3,
			UniquePackages: 3,
			Ecosystems: []source.CountBucket{
				{Label: "npm", Count: 2, Share: 66.7},
				{Label: "PyPI", Count: 1, Share: 33.3},
			},
			Namespaces: []source.CountBucket{
				{Label: "@acme", Count: 2, Share: 66.7},
			},
			Age: []source.CountBucket{
				{Label: "NEW (≤7d)", Count: 2, Share: 66.7},
				{Label: "RECENT (8–30d)", Count: 1, Share: 33.3},
			},
		},
		Corpus: source.CorpusStats{Source: "osv", IndexedPackages: 12000},
	}
	writeFeedDashboard(&buf, o.color(), result)
	out := buf.String()
	for _, want := range []string{
		"Malicious package & supply-chain intelligence",
		"activity · published in last 24h · 3 advisories",
		"top ecosystems",
		"most impacted namespaces",
		"@acme",
		"disclosure age",
		"quick start",
		"depx feed",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in dashboard:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"indexed corpus", "sync pending"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("dashboard should no longer show %q:\n%s", unwanted, out)
		}
	}
}
