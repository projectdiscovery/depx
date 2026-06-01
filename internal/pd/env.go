package pd

import (
	"os"
	"strings"
)

const DefaultAPIURL = "https://github.projectdiscovery.io"

// Enabled reports whether depx should use the PD GitHub Scan API as the intel source.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEPX_INTEL_SOURCE"))) {
	case "pd", "github", "ghscan":
		return Token() != ""
	case "osv", "":
		if os.Getenv("DEPX_PD_API") == "1" || strings.EqualFold(os.Getenv("DEPX_PD_API"), "true") {
			return Token() != ""
		}
		return false
	default:
		return false
	}
}

func APIURL() string {
	if v := strings.TrimSpace(os.Getenv("DEPX_PD_API_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return DefaultAPIURL
}

func Token() string {
	if v := strings.TrimSpace(os.Getenv("DEPX_PD_API_TOKEN")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("DEPX_PD_TOKEN"))
}

func OSVBaseURL() string {
	return APIURL() + "/v1"
}
