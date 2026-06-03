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

1. `make fmt-check` — code must be gofmt-clean
2. `make vet` — `go vet ./...`
3. `make test` — unit tests
4. `make lint` — golangci-lint (same config as CI)
5. `make vulncheck` — `govulncheck ./...` (no new reachable vulns in depx-owned code paths; known transitive findings from `osv-scalibr` → docker/go-git are tracked upstream)

End-to-end tests live under `e2e/` and run with the main test suite.

## Code style

- Match existing patterns in the package you are editing
- Keep CLI output stable; gate UX changes behind flags when possible
- JSON output uses the versioned envelope in `internal/output` (`schema_version`, `command`, `depx_version`, `data`)
- Prefer focused unit tests with `internal/intel/inteltest` stubs over heavy integration mocks

## Reporting issues

Include depx version (`depx version`), OS/arch, and a minimal repro command. For upstream data issues (missing MAL entries), link the OSV advisory ID when available.
