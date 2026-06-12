  <h1 align="center">depx</h1>

<h4 align="center">Malicious package &amp; supply-chain intelligence</h4>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/report/github.com/projectdiscovery/depx"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/depx"></a>
<a href="https://github.com/projectdiscovery/depx/releases"><img src="https://img.shields.io/github/release/projectdiscovery/depx"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-depx">Running depx</a> •
  <a href="#json-output">JSON</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

<p align="center">
  <img src="docs/assets/depx-feed-screenshot.png" alt="depx feed: latest malicious packages" width="95%">
</p>

---

**depx** is a fast, passive supply-chain intelligence CLI. It tells you whether a package is **known malicious** (hijacked publishes, credential stealers, install-script backdoors) by matching against [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) data (`MAL-*`, OSV format) and a live intelligence feed curated from [X (Grok API)](https://x.com), refreshed hourly.

It answers four questions in seconds:

1. **What got compromised recently?** The live feed of newly disclosed malicious packages.
2. **Is this specific package safe to install?** Check any package before you add it.
3. **Have I already installed anything malicious on my system?** Audit local lockfiles and SBOMs.
4. **Do my GitHub organization's projects ship any malicious packages?** Scan whole orgs and repos.

# Features

- **Intelligence dashboard**: default view with activity, ecosystems, impacted namespaces, and disclosure age.
- **Compromised package feed**: time-ordered cards via `depx feed` (or `--list` for one line per result).
- **Local dependency audit**: scan lockfiles & SBOMs against a compiled local index.
- **GitHub org & repo audit**: pull dependency-graph SBOM exports and audit at scale.
- **CI-ready**: stable exit codes, `--require-clean` gate, SARIF export, and a versioned JSON envelope.
- **Instant package verdicts**: check any `ecosystem:name` ref, bare name, or piped list.
- **False-positive control**: `--exclude-pkg` file to suppress known-good packages from audit findings.
- **Fast & passive**: local cache, background sync; read-only, never touches your apps.

# Installation

```bash
curl -sfL https://raw.githubusercontent.com/projectdiscovery/depx/main/scripts/install.sh | sh
```

Downloads the latest release for your OS/arch (or builds with `go install` as fallback). The script verifies the binary and updates your shell `PATH` when needed.

**From source** (requires **Go 1.25+**):

```bash
git clone https://github.com/projectdiscovery/depx.git
cd depx
make build
./bin/depx --help
```

Or install with Go directly:

```bash
go install github.com/projectdiscovery/depx/cmd/depx@latest
```

Prebuilt binaries are also on the [GitHub releases](https://github.com/projectdiscovery/depx/releases) page.

# Usage

```bash
depx --help
```

Core commands and flags:

```yaml
Usage:
  depx [flags]
  depx [command]

Available Commands:
  feed        Show recently disclosed malicious packages (cards)
  audit       Audit dependencies for malicious packages (default: $HOME)
  github      Audit GitHub repositories via dependency-graph SBOM
  search      Search known malicious packages by name (local index)
  id          Lookup advisory by ID
  version     Show version and check for updates
  update      Update depx to the latest version

Global flags:
  -j, --json                   Machine-readable JSON output
  -V, --version                Show version and exit
  -e, --ecosystem string       Restrict lookup to one ecosystem (npm, PyPI, Go, ...)
  -v, --verbose                Extra audit/github detail
      --silent                 Suppress banner and version info
      --no-color               Disable ANSI colors
      --config string          Config file path
      --update                 Update depx to the latest version
      --disable-update-check   Disable the update check

Default command (intelligence dashboard):
      --since string           Feed time window (default "3d")
  -n, --limit int              Dashboard/feed entry cap on default command

depx feed:
      --since string           Feed time window (default "3d")
  -n, --limit int              Result limit
      --list                   One header line per result

depx search:
  -n, --limit int              Max results shown (default 25)
      --list                   One header line per result

depx audit / depx github:
      --require-clean          Exit 1 if any malicious package is found
      --exclude-pkg string     File of ecosystem:package lines to exclude from findings
  -o, --output string          Write export file(s) to this path or basename
      --output-format string   Comma-separated export formats: json, csv, txt (default: json)
      --sarif-export string    Write SARIF 2.1.0 report to this path
      --sbom-export string     Write audited dependency SBOM (audit only)
      --sbom-format string     SBOM format: cyclonedx (default) or spdx

depx github:
  -n, --limit int              Max repos for org/user targets (default 100 with token, 10 without)

depx id:
      --raw                    Raw OSV record only
```

# Running depx

### 1. Intelligence dashboard (default)

```bash
depx                    # dashboard for last 3 days
depx --since 7d         # widen the time window
depx -e npm             # npm-only dashboard
depx feed               # card feed (no dashboard)
depx feed --list        # one line per advisory
depx -j                 # JSON for dashboards / pipelines
```

### 2. Audit your dependencies

Scans lockfiles and SBOMs against a **local malicious-package index**, instant after the first run. With no path, depx sweeps `$HOME` for projects and global installs.

```bash
depx audit              # sweep $HOME for projects + global installs
depx audit ./my-app     # a single project tree
depx audit ./bom.cdx.json   # a CycloneDX / SPDX file
```

Supports npm, PyPI, Go, Cargo, RubyGems, Maven/Gradle lockfiles plus CycloneDX / SPDX SBOMs.

**Suppress false positives.** When a package is flagged that you've verified is safe, pass `--exclude-pkg` (on `audit` or `github`) a file of newline-separated `ecosystem:package` entries to drop from findings:

```bash
depx audit ./my-app --exclude-pkg .depxignore
depx github google --exclude-pkg .depxignore
```

```text
# .depxignore: packages to exclude from findings
npm:internal-tool
PyPI:requests
*:shared-lib        # '*' matches any ecosystem
```

### 3. Audit GitHub repos & orgs

Uses GitHub's dependency-graph SBOM exports. Set `GITHUB_TOKEN` for private repos and org discovery.

```bash
depx github projectdiscovery/depx
depx github google
depx github
```

Unauthenticated GitHub access is rate-limited to ~60 requests/hour, so without a token org/user scans default to **10 repos** (vs **100** with a token). Set `GITHUB_TOKEN`, `GH_TOKEN`, or `DEPX_GITHUB_TOKEN` (or raise it explicitly with `-n`) to scan more.

### 4. Check a single package or advisory

```bash
depx npm:lodash
depx id MAL-2026-4343
depx search redhat
```

### 5. Gate it in CI

`--require-clean` exits non-zero the moment a malicious package is found.

```bash
depx audit . --require-clean        # fail the build if anything is malicious
depx github google --require-clean -j
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Clean / success |
| `1` | `--require-clean` and malicious packages found |
| `2` | Usage error |
| `3` | Upstream unavailable |

# JSON output

Every `-j` response uses a stable, versioned envelope so it's safe to build on.

```json
{
  "schema_version": "1",
  "command": "check",
  "depx_version": "v0.1.0",
  "data": {
    "total": 1,
    "results": [
      {
        "ref": "npm:evil-pkg",
        "purl": "pkg:npm/evil-pkg",
        "verdict": "malicious",
        "confidence": "high",
        "ids": ["MAL-2026-4343"],
        "package_ecosystem": "npm",
        "package_name": "evil-pkg",
        "registry_url": "https://www.npmjs.com/package/evil-pkg",
        "advisories": [
          {
            "id": "MAL-2026-4343",
            "url": "https://github.com/ossf/malicious-packages/blob/main/osv/npm/MAL-2026-4343.json",
            "summary": "Malicious code in evil-pkg (npm)",
            "modified_at": "2026-06-01T12:00:00Z",
            "published_at": "2026-06-01T10:00:00Z"
          }
        ]
      }
    ]
  }
}
```

A clean package returns `"verdict": "clean"`. Bare-name checks may include `checked_ecosystems`, `matched_ecosystems`, and `found_ecosystems` when searching all ecosystems.

Schemas live in [`schema/v1/`](schema/v1/).

# License

depx is distributed under the [MIT License](LICENSE).

<p align="center">
<a href="https://discord.gg/projectdiscovery">Join our Discord</a> • built with ❤️ by the <a href="https://projectdiscovery.io">ProjectDiscovery</a> team
</p>
