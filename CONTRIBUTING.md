# Contributing to depx

Thanks for helping improve depx. This project follows the same conventions as other ProjectDiscovery Go tools (nuclei, httpx, subfinder).

## Development setup

Requires **Go 1.25+**.

```bash
git clone https://github.com/projectdiscovery/depx.git
cd depx
make build
make test
```

Point depx at mock OSV endpoints for offline work:

```bash
export DEPX_OSV_URL=http://127.0.0.1:8080/v1
export DEPX_MODIFIED_INDEX_URL=http://127.0.0.1:8080/modified_id.csv
./bin/depx --disable-update-check --silent npm:lodash
```

## Before opening a PR

Run the full local CI gate:

```bash
make ci
```

This runs `fmt-check`, `lint`, `vulncheck`, `build`, `test`, and race checks — the same jobs as `.github/workflows/build-test.yml`.

Individual targets: `make fmt-check`, `make lint`, `make vulncheck`, `make test`.

`make lint` downloads the official golangci-lint binary (`v2.5.0+`, built with Go 1.25). A Homebrew or `go install` linter built with Go 1.24 will fail against this repo's `go 1.25` module.

`make vulncheck` — no new reachable vulns in depx-owned code paths; known transitive findings from `osv-scalibr` → docker/go-git are tracked upstream.

End-to-end tests live under `e2e/` and run with the main test suite.

## Code style

- Match existing patterns in the package you are editing
- Keep CLI output stable; gate UX changes behind flags when possible
- JSON output uses the versioned envelope in `internal/output` (`schema_version`, `command`, `depx_version`, `data`)
- Prefer focused unit tests with `internal/intel/inteltest` stubs over heavy integration mocks

## Reporting issues

Include depx version (`depx version`), OS/arch, and a minimal repro command. For upstream data issues (missing MAL entries), link the OSV advisory ID when available.
