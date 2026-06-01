<h1 align="center">depx</h1>

<h4 align="center">Dependency explorer and auditor — surface malicious packages and supply-chain risks</h4>

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
  <a href="#data--caching">Data</a> •
  <a href="#json-output">JSON</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

---

**depx** is a fast, passive supply-chain intelligence CLI. It tells you whether a package is **known malicious** — hijacked publishes, credential stealers, install-script backdoors — by matching against the [OSV malicious-packages](https://osv.dev) corpus (`MAL-*`).

It answers three questions in seconds: *what got compromised recently?*, *is this specific package safe to install?*, and *do I already ship anything malicious?* — across local lockfiles, SBOMs, and whole GitHub organizations.

# Features

- **Compromised package feed** — time-ordered stream of newly disclosed malicious packages.
- **Local dependency audit** — scan lockfiles & SBOMs against a compiled local index.
- **GitHub org & repo audit** — pull dependency-graph SBOM exports and audit at scale.
- **CI-ready** — stable exit codes, `--require-clean` gate, and a versioned JSON envelope.
- **Instant package verdicts** — check any `ecosystem:name` ref, bare name, or piped list.
- **Fast & passive** — local cache, no per-package network calls; read-only, never touches your apps.

# Installation

depx requires **Go 1.24** or later.

```bash
go install github.com/projectdiscovery/depx/cmd/depx@latest
```

Or build from source:

```bash
git clone https://github.com/projectdiscovery/depx.git
cd depx
make build
./bin/depx --help
```

# Usage

```bash
depx --help
```

This displays help for the tool. Here are the core commands and flags:

```yaml
Usage:
  depx [flags]
  depx [command]

Available Commands:
  audit       Audit dependencies for malicious packages (default: $HOME)
  github      Audit GitHub repositories via dependency-graph SBOM
  search      Search known malicious packages by name
  id          Lookup advisory by ID
  version     Show version and check for updates
  update      Update depx to the latest version

Flags:
  -j, --json              Machine-readable JSON output
  -e, --ecosystem string  Restrict lookup to one ecosystem (npm, PyPI, Go, ...)
      --since string      Feed time window (default "24h")
  -n, --limit int         Result limit
  -v, --verbose           Extra audit/github detail
      --silent            Suppress banner and version info
      --no-color          Disable ANSI colors
      --timeout duration  Request timeout
      --config string     Config file path
```

# Running depx

### 1. Watch the compromised-package feed

The default command streams recently disclosed malicious packages.

```bash
depx                    # newly disclosed malicious packages (last 24h)
depx --since 7d         # widen the time window
depx -j                 # JSON for dashboards / pipelines
```

### 2. Audit your dependencies

Scans lockfiles and SBOMs against a **local malicious-package index** — fast after the first run. With no path, depx sweeps `$HOME` for projects and global installs.

```bash
depx audit              # sweep $HOME for projects + global installs
depx audit ./my-app     # a single project tree
depx audit ./bom.cdx.json   # a CycloneDX / SPDX file
```

Supports npm, PyPI, Go, Cargo, RubyGems, Maven/Gradle lockfiles plus CycloneDX / SPDX SBOMs.

### 3. Audit GitHub repos & orgs

Uses GitHub's dependency-graph SBOM exports. Set `GITHUB_TOKEN` for private repos and org discovery.

```bash
depx github owner/repo  # a single repository
depx github acme-corp   # every repo in an org/user (capped by -n)
depx github             # with a token set, every repo you can access
```

### 4. Gate it in CI

`--require-clean` exits non-zero the moment a malicious package is found.

```bash
depx audit . --require-clean        # fail the build if anything is malicious
depx github acme-corp --require-clean -j
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Clean / success |
| `1` | `--require-clean` and malicious packages found |
| `2` | Usage error |
| `3` | Upstream unavailable |

### Check a single package or advisory

```bash
depx npm:lodash         # explicit ecosystem
depx lodash             # bare name → all ecosystems
echo apkeep | depx      # stdin, one ref per line
depx id MAL-2026-4343   # full advisory record
depx search apkeep      # search corpus by package name
```

# Data & caching

- **Source** — the [OSV.dev](https://osv.dev) malicious-packages database (`MAL-*`), plus npm/PyPI registry metadata for richer package checks. Set `DEPX_INTEL_SOURCE=pd` to use ProjectDiscovery's GitHub Scan corpus instead (requires `DEPX_PD_API_TOKEN`).
- **Offline baseline** — release binaries embed gzip tarballs of the OSV and PD malicious-package indexes. On first run (or when your local cache is older than the embedded baseline), depx extracts the bundle into `~/.cache/depx` so search and audit work without network access.
- **Cache & sync** — `~/.cache/depx` holds a manifest-tracked malicious-package index, feed catalog, and GitHub SBOM cache. When online, depx refreshes deltas in the background (every ~5 minutes). Background sync fails silently offline and serves the last good index.
- **Config** — optional `~/.config/depx/config.yaml`.

# JSON output

Every `-j` response uses a stable, versioned envelope so it's safe to build on.

```json
{
  "schema_version": "1",
  "command": "feed",
  "depx_version": "v0.1.0",
  "data": {}
}
```

Schemas live in [`schema/v1/`](schema/v1/).

# Development

```bash
make test            # unit + e2e
make build
make bundles-minimal # dev embedded stubs (no network)
make bundles         # full OSV + PD release bundles
```

CI matches other ProjectDiscovery Go tools: `build-test`, `release-test`, `release-binary`, and `dep-auto-merge`. Push a `v*` tag to release; GoReleaser ships cross-platform zips with full embedded intel when `DEPX_PD_API_TOKEN` is set.

# License

depx is distributed under the [MIT License](LICENSE).

<p align="center">
<a href="https://discord.gg/projectdiscovery">Join our Discord</a> • built with ❤️ by the <a href="https://projectdiscovery.io">ProjectDiscovery</a> team
</p>
