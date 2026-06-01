#!/usr/bin/env bash
# Side-by-side wall-clock benchmark: depx with OSV (default) vs PD intel source.
# Usage: DEPX_PD_API_TOKEN=... ./scripts/bench-depx-cli.sh

set -euo pipefail

DEPX_BIN="${DEPX_BIN:-$(cd "$(dirname "$0")/.." && pwd)/bin/depx}"
PD_TOKEN="${DEPX_PD_API_TOKEN:-${PD_API_TOKEN:-}}"
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
echo -e "source\tscenario\tseconds\texit\tnote" > "$RESULTS"

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
  local source=$1 scenario=$2 cache=$3 config=$4
  shift 4
  local -a env_args=()
  if [[ "$source" == "pd" ]]; then
    if [[ -z "$PD_TOKEN" ]]; then
      echo -e "${source}\t${scenario}\t-\t-\tno PD token" >> "$RESULTS"
      return 0
    fi
    env_args=(DEPX_INTEL_SOURCE=pd DEPX_PD_API_TOKEN="$PD_TOKEN")
  else
    env_args=(DEPX_INTEL_SOURCE=osv)
    unset DEPX_PD_API DEPX_PD_API_TOKEN DEPX_PD_TOKEN 2>/dev/null || true
  fi

  local log="$WORKDIR/results/${source}-${scenario// /_}.log"
  local start end elapsed rc=0
  start=$(python3 -c 'import time; print(time.perf_counter())')
  env "${env_args[@]}" "$DEPX_BIN" --config "$config" --silent --disable-update-check "$@" \
    >"$log" 2>&1 || rc=$?
  end=$(python3 -c 'import time; print(time.perf_counter())')
  elapsed=$(python3 -c "print(f'{$end - $start:.2f}')")

  local note=""
  if [[ $rc -ne 0 ]]; then
    note=$(tail -1 "$log" | head -c 120)
  fi
  echo -e "${source}\t${scenario}\t${elapsed}\t${rc}\t${note}" >> "$RESULTS"
  printf "  %-6s %-32s %8ss  exit=%s\n" "$source" "$scenario" "$elapsed" "$rc"
}

bench_source() {
  local source=$1
  local cache="$WORKDIR/cache-${source}"
  local cfg="$WORKDIR/config-${source}.yaml"
  write_cfg "$cache" "$cfg"

  echo ""
  echo "=== backend: $source (cache: $cache) ==="

  run_one "$source" "feed default" "$cache" "$cfg" -j -n 10
  run_one "$source" "feed since 7d" "$cache" "$cfg" -j --since 7d -n 50
  run_one "$source" "check npm:lodash" "$cache" "$cfg" npm:lodash -j
  run_one "$source" "check pypi:apkeep@0.1.0" "$cache" "$cfg" pypi:apkeep@0.1.0 -j
  run_one "$source" "check bare lodash" "$cache" "$cfg" lodash -j
  run_one "$source" "check stdin x2" "$cache" "$cfg" -j <<< $'lodash\napkeep'
  run_one "$source" "id MAL-2026-3431" "$cache" "$cfg" id MAL-2026-3431 -j

  # cold local scan index
  rm -rf "$cache/mal" "$cache/feed" "$cache/sync" 2>/dev/null || true
  run_one "$source" "audit project cold" "$cache" "$cfg" audit "$FIXTURE" -j -q
  run_one "$source" "audit project warm" "$cache" "$cfg" audit "$FIXTURE" -j -q
  run_one "$source" "audit SBOM" "$cache" "$cfg" audit "$SBOM" -j -q

  # home audit (warm index from above)
  run_one "$source" "audit \$HOME warm" "$cache" "$cfg" audit "$HOME_DIR" -j -q

  # github (needs GITHUB_TOKEN)
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    run_one "$source" "github repo" "$cache" "$cfg" github projectdiscovery/depx -j -q
    run_one "$source" "github org -n2" "$cache" "$cfg" github projectdiscovery -n 2 -j -q
  else
    echo -e "${source}\tgithub repo\t-\t-\tno GITHUB_TOKEN" >> "$RESULTS"
    echo -e "${source}\tgithub org -n2\t-\t-\tno GITHUB_TOKEN" >> "$RESULTS"
    echo "  (skip github — GITHUB_TOKEN unset)"
  fi
}

main() {
  echo "depx CLI benchmark"
  echo "binary:  $DEPX_BIN"
  echo "workdir: $WORKDIR"
  echo "PD token: ${PD_TOKEN:+set}"

  bench_source osv
  bench_source pd

  echo ""
  echo "=== Summary (seconds) ==="
  python3 - "$RESULTS" <<'PY'
import sys
from collections import defaultdict

path = sys.argv[1]
rows = []
with open(path) as f:
    next(f)
    for line in f:
        parts = line.rstrip("\n").split("\t", 4)
        if len(parts) < 4:
            continue
        src, scen, sec, rc = parts[0], parts[1], parts[2], parts[3]
        rows.append((scen, src, sec, rc))

by_scen = defaultdict(dict)
order = []
for scen, src, sec, rc in rows:
    if scen not in by_scen:
        order.append(scen)
    by_scen[scen][src] = (sec, rc)

print(f"{'Scenario':<32} {'OSV (s)':>10} {'PD (s)':>10} {'PD/OSV':>10}")
print("-" * 64)
for scen in order:
    o = by_scen[scen].get("osv", ("-", "-"))
    p = by_scen[scen].get("pd", ("-", "-"))
    osv_s, pd_s = o[0], p[0]
    ratio = "-"
    try:
        ratio = f"{float(pd_s)/float(osv_s):.2f}x"
    except (ValueError, ZeroDivisionError):
        pass
    osv_out = osv_s if osv_s != "-" else "-"
    pd_out = pd_s if pd_s != "-" else "-"
    if o[1] != "0" and o[1] != "-":
        osv_out += f"(!{o[1]})"
    if p[1] != "0" and p[1] != "-":
        pd_out += f"(!{p[1]})"
    print(f"{scen:<32} {osv_out:>10} {pd_out:>10} {ratio:>10}")

print(f"\nRaw TSV: {path}")
print(f"Logs:    {path.rsplit('/', 1)[0]}/")
PY
}

main "$@"
