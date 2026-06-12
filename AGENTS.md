# AGENTS.md — depx development guide

This file captures conventions for AI agents and contributors working on [depx](https://github.com/projectdiscovery/depx).

## Project overview

`depx` is a Go CLI for supply-chain attack intelligence: compromised-package feed, package/advisory lookups, local lockfile/SBOM scanning, and GitHub repository scanning via dependency-graph SBOM exports.

## Commands (user-facing)

| Command | Purpose |
|---------|---------|
| `depx` (default) | Recent compromised packages feed |
| `depx <ref>` / stdin | Check package refs or advisory IDs |
| `depx audit [path...]` | **Local** lockfile/SBOM audit only |
| `depx search <query>` | Search malicious packages by name |
| `depx github [target...]` | **GitHub-only** repo/org scanning |
| `depx id <MAL\|GHSA\|...>` | Advisory lookup |
| `depx version` / `depx --version` / `depx update` | Version info and self-update |

**Do not** add GitHub repo auditing to `depx audit`. GitHub targets belong exclusively on `depx github`. If audit receives a `github:` ref without a configured client, return a clear error pointing users to `depx github`.

## Code layout

```
cmd/depx/           main entry
internal/cli/       Cobra commands (split by concern)
  root.go           root command, flags, init
  feed.go           default feed
  check.go          implicit package checks
  id.go             advisory ID lookup
  audit_run.go      shared audit wiring (buildAuditOptions, runAudit)
  github.go         github subcommand
internal/lockfile/  canonical root lockfile names + ecosystem mapping
internal/github/    GitHub API client, parsing, SBOM/lockfile fetch
internal/audit/      local discovery, extraction, malicious-package matching
internal/intel/     Provider interface, backed by the local inventory index
internal/inventory/  inventory export model + streaming gzip fetch
internal/malindex/   in-memory malicious-package index (search + match + lookup)
internal/sync/    manifest-tracked hourly inventory sync (keeps last good index on failure)
internal/output/    JSON + human card rendering
e2e/                CLI integration tests
```

Keep `internal/cli/root.go` thin — add new command logic in dedicated files, not by growing root.go.

## Single sources of truth

### Root lockfiles

All root lockfile names live in **`internal/lockfile/lockfile.go`** (`RootNames`, `IsRootName`, `Ecosystem`).

- `internal/audit/discover.go` — local discovery
- `internal/github/lockfiles.go` — GitHub Contents API fetch
- `internal/audit/audit.go` — `inferEcoFromPath`

**Never duplicate** lockfile name lists elsewhere.

### GitHub target parsing

All GitHub URL/owner/repo parsing goes through **`internal/github/repo.go`**:

- `ParseTarget` — full parse (repo or org)
- `ParseRepo` — single repo only (wraps `ParseTarget`)
- `Repo.URL()` — canonical `https://github.com/owner/repo`

Do not reimplement URL parsing in CLI or audit packages.

### GitHub API errors

Use **`github.APIError`** and `errors.As` / `AsAPIError` — avoid string-matching `"status 404"` in new code.

### Audit options

CLI audit wiring is centralized in **`internal/cli/audit_run.go`**:

- `buildAuditOptions(ghClient)` — shared Options construction
- `runAudit(cmd, paths, ghClient)` — nil client for local audit; real client for `depx github`

Both `newAuditCmd` and `runGitHub` must use these helpers.

### Limit flags (`-n`)

`-n` / `--limit` semantics differ by command:

- **Default feed** (`depx -n N`): caps feed entries (`config.NormalizeFeedLimit`)
- **`depx search -n N`**: caps search results shown (default from config feed limit; footer shows total matches)
- **`depx github -n N`**: caps repos when target is org/user (`config.NormalizeGitHubRepoLimit`). Default depends on auth: `DefaultGitHubRepoLimit` (100) with a token, `DefaultGitHubRepoLimitUnauth` (10) without, to stay within GitHub's ~60 req/hr unauthenticated budget.

Both use shared `config.normalizeLimit` — extend that helper rather than duplicating validation.

## Output cards

Malicious advisory cards share a header via **`writeMaliciousCardHeader`** and body via **`writeFeedCard`**. Feed, search, malicious check, and `id` lookup should all route through those helpers; audit findings add context lines via **`writeAuditFindingCard`**.

## E2E tests

- **`e2e/harness_test.go`**: `TestMain` builds the binary once; use `binPath(t)`.
- **`e2e/mock_source_test.go`**: gzipped inventory export mock + JSON assertions (`mockSourceServer`, `sourceEnv`).
- **`e2e/mock_github_test.go`**: GitHub break-test mock server.

Do not rebuild the binary per test or duplicate mock servers across files.

Break/adversarial tests belong in `e2e/break_test.go` and `e2e/break_github_test.go`.

## Change discipline

1. **Minimal diffs** — match existing style; no drive-by refactors.
2. **No shell completion subcommand** — Cobra default completion is disabled.
3. **No `depx check` subcommand** — checks are `depx <ref>` or stdin; `depx check <ref>` is an optional alias (keyword stripped at root).
4. **Errors** — use `internal/apperr` (`Usage`, `Upstream`); wrapped causes must appear in `Error()`.
5. **CI gate before commit** — run `make ci` and ensure it passes before considering work ready to commit or hand off. Do not skip this for “small” changes. If `make ci` fails, fix the failure or call out the blocker explicitly; do not treat the task as done.
6. **Tests** — add unit/e2e tests for non-trivial parsing, API, or CLI behavior; `make ci` already runs `go test ./... -count=1` and race tests.
7. **README** — update command tables when user-facing behavior changes.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `DEPX_GITHUB_TOKEN` / `GITHUB_TOKEN` | GitHub API auth |
| `DEPX_GITHUB_API_URL` | Override API base (tests/mocks) |
| `DEPX_SOURCE_URL` | Override the inventory export URL (tests / self-hosted mirror) |

depx has a single intel source: the ProjectDiscovery malicious-package inventory
export — one unauthenticated, gzipped JSON document refreshed hourly upstream
(default `https://github.projectdiscovery.io/github/malicious/export`).

On first run, `depx` downloads the export, decompresses it on the fly, and builds
a local index in `~/.cache/depx`. **All** intel operations (feed, check, audit,
search, id) then run entirely against that local index. Background sync re-pulls
the export hourly; if a pull fails (network, decompression, parse), depx keeps
serving the last good index — there is no fallback source.

## CI / release

Workflows match other ProjectDiscovery Go CLIs (`subfinder`, `httpx`):

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `build-test.yml` | PR (Go changes) | golangci-lint, gofmt, govulncheck, cross-OS build/test/race |
| `release-test.yml` | PR | GoReleaser snapshot build |
| `release-binary.yml` | `v*` tag push | GoReleaser release (binaries) |
| `dep-auto-merge.yml` | Dependabot PRs | Auto-merge dependency updates |

**Local CI gate:** run `make ci` before commit. It mirrors `build-test.yml` on one machine:

```bash
make ci
# fmt-check → lint → vulncheck → build → cross-build → test → race → race-build
```

`cross-build` compiles linux/amd64, linux/arm64, and windows/amd64 (same as GoReleaser). Native `go build` on macOS skips Linux-only packages (e.g. `containerd/oci`), so cross-build is required to catch release failures locally.

`make lint` downloads the official golangci-lint binary (Go 1.25–compatible). Do not use a Homebrew/`go install` linter built with Go 1.24 against this repo.

Release optional secrets: `RELEASE_SLACK_WEBHOOK`, `DISCORD_WEBHOOK_*`, `DEPENDABOT_PAT`.

## Adding a new root lockfile

1. Add name to `internal/lockfile/lockfile.go` (`RootNames` + `Ecosystem`).
2. Ensure osv-scalibr plugin exists in `internal/audit/audit.go` `lockfilePlugins` if extraction is needed.
3. Add unit/e2e coverage if behavior is non-obvious.

## Adding a new subcommand

1. Create `internal/cli/<name>.go` with `new<Name>Cmd()`.
2. Register in `NewRootCmd()` and `isSubcommand()`.
3. Add e2e smoke/break cases as appropriate.
4. Document in README.
