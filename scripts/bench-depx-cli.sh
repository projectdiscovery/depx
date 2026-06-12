#!/usr/bin/env bash
# Wall-clock benchmark for depx against the malicious-package inventory source.
# Usage: ./scripts/bench-depx-cli.sh
#   DEPX_SOURCE_URL=...  optional override / self-hosted mirror
#   GITHUB_TOKEN=...     optional, enables the github scenarios

set -euo pipefail

DEPX_BIN="${DEPX_BIN:-$(cd "$(dirname "$0")/.." && pwd)/bin/depx}"
WORKDIR="${WORKDIR:-$(mktemp -d /tmp/depx-bench-XXXXXX)}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$REPO_ROOT/testdata/fixtures/clean-project"
SBOM="$REPO_ROOT/testdata/fixtures/clean-sbom/bom.cdx.json"
HOME_DIR="${HOME:-$HOME}"

if [[ ! -x "$DEPX_BIN" ]]; then
  echo "Building depx..."
  (cd "$REPO_ROOT" && go build -o "$DEPX_BIN" ./cmd/depx)
fi

mkdir -p "$WORKDIR/results"
RESULTS="$WORKDIR/results/times.tsv"
echo -e "scenario\tseconds\texit\tnote" > "$RESULTS"

write_cfg() {
  local cache_dir=$1
  mkdir -p "$cache_dir"
  cat > "$2" <<EOF
cache_dir: $cache_dir
timeout: 120s
feed:
  cache_ttl: 1h
  limit: 25
  since: 24h
EOF
}

run_one() {
  local scenario=$1 cache=$2 config=$3
  shift 3

  local log="$WORKDIR/results/${scenario// /_}.log"
  local start end elapsed rc=0
  start=$(python3 -c 'import time; print(time.perf_counter())')
  "$DEPX_BIN" --config "$config" --silent --disable-update-check "$@" \
    >"$log" 2>&1 || rc=$?
  end=$(python3 -c 'import time; print(time.perf_counter())')
  elapsed=$(python3 -c "print(f'{$end - $start:.2f}')")

  local note=""
  if [[ $rc -ne 0 ]]; then
    note=$(tail -1 "$log" | head -c 120)
  fi
  echo -e "${scenario}\t${elapsed}\t${rc}\t${note}" >> "$RESULTS"
  printf "  %-32s %8ss  exit=%s\n" "$scenario" "$elapsed" "$rc"
}

bench() {
  local cache="$WORKDIR/cache"
  local cfg="$WORKDIR/config.yaml"
  write_cfg "$cache" "$cfg"

  echo ""
  echo "=== inventory source (cache: $cache) ==="
  echo "source: ${DEPX_SOURCE_URL:-default export}"

  run_one "feed default" "$cache" "$cfg" -j -n 10
  run_one "feed since 7d" "$cache" "$cfg" -j --since 7d -n 50
  run_one "check npm:lodash" "$cache" "$cfg" npm:lodash -j
  run_one "check pypi:apkeep@0.1.0" "$cache" "$cfg" pypi:apkeep@0.1.0 -j
  run_one "check bare lodash" "$cache" "$cfg" lodash -j
  run_one "check stdin x2" "$cache" "$cfg" -j <<< $'lodash\napkeep'
  run_one "id MAL-2026-3431" "$cache" "$cfg" id MAL-2026-3431 -j

  # cold local index
  rm -rf "$cache/mal" "$cache/feed" "$cache/sync" 2>/dev/null || true
  run_one "audit project cold" "$cache" "$cfg" audit "$FIXTURE" -j -q
  run_one "audit project warm" "$cache" "$cfg" audit "$FIXTURE" -j -q
  run_one "audit SBOM" "$cache" "$cfg" audit "$SBOM" -j -q
  run_one "audit \$HOME warm" "$cache" "$cfg" audit "$HOME_DIR" -j -q

  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    run_one "github repo" "$cache" "$cfg" github projectdiscovery/depx -j -q
    run_one "github org -n2" "$cache" "$cfg" github projectdiscovery -n 2 -j -q
  else
    echo -e "github repo\t-\t-\tno GITHUB_TOKEN" >> "$RESULTS"
    echo -e "github org -n2\t-\t-\tno GITHUB_TOKEN" >> "$RESULTS"
    echo "  (skip github — GITHUB_TOKEN unset)"
  fi
}

main() {
  echo "depx CLI benchmark"
  echo "binary:  $DEPX_BIN"
  echo "workdir: $WORKDIR"

  bench

  echo ""
  echo "=== Summary (seconds) ==="
  python3 - "$RESULTS" <<'PY'
import sys

path = sys.argv[1]
print(f"{'Scenario':<32} {'Seconds':>10} {'Exit':>6}")
print("-" * 50)
with open(path) as f:
    next(f)
    for line in f:
        parts = line.rstrip("\n").split("\t", 3)
        if len(parts) < 3:
            continue
        scen, sec, rc = parts[0], parts[1], parts[2]
        print(f"{scen:<32} {sec:>10} {rc:>6}")

print(f"\nRaw TSV: {path}")
print(f"Logs:    {path.rsplit('/', 1)[0]}/")
PY
}

main "$@"
