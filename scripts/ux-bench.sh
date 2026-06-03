#!/usr/bin/env bash
# Benchmark depx command UX + timing for a given cache directory.
# Usage: ./scripts/ux-bench.sh /path/to/cache [depx-binary]
set -euo pipefail

CACHE_DIR="${1:?cache dir required}"
DEPX_BIN="${2:-./depx}"
CFG="$(mktemp -t depx-ux-cfg.XXXXXX.yaml)"
trap 'rm -f "$CFG"' EXIT

cat >"$CFG" <<EOF
cache_dir: ${CACHE_DIR}
feed:
  cache_ttl: 1h
timeout: 30s
EOF

export NO_COLOR=1
	unset DEPX_OSV_URL DEPX_MODIFIED_INDEX_URL 2>/dev/null || true

CLEAN_PROJECT="$(cd "$(dirname "$0")/.." && pwd)/testdata/fixtures/clean-project"

run_cmd() {
  local label="$1"
  shift
  local start end elapsed exit_code=0 preview
  start=$(date +%s.%N)
  local out
  out=$(env -u DEPX_OSV_URL -u DEPX_MODIFIED_INDEX_URL \
    "$DEPX_BIN" --disable-update-check --config "$CFG" "$@" </dev/null 2>&1) || exit_code=$?
  end=$(date +%s.%N)
  elapsed=$(awk -v s="$start" -v e="$end" 'BEGIN { printf "%.0fms", (e-s)*1000 }')
  preview=$(printf '%s' "$out" | head -n 8 | sed 's/\r$//' | tr '\n' ' | ')
  if [[ ${#preview} -gt 200 ]]; then
    preview="${preview:0:200}..."
  fi
  printf '%-32s %8s  exit=%-3s  %s\n' "$label" "$elapsed" "$exit_code" "$preview"
}

echo ""
echo "=== UX bench: cache=${CACHE_DIR} ==="
echo ""

run_cmd "dashboard" 
run_cmd "feed" feed
run_cmd "feed --list" feed --list
run_cmd "feed -j -n 3" feed -j -n 3
run_cmd "feed --since 24h" feed --since 24h
run_cmd "search apk" search apk
run_cmd "search apk --list" search apk --list
run_cmd "search apk -j" search apk -j
run_cmd "search apkeep" search apkeep
run_cmd "audit clean-project" audit "$CLEAN_PROJECT"
run_cmd "audit -j clean-project" audit -j "$CLEAN_PROJECT"
run_cmd "check apkeep" check apkeep
run_cmd "check -j apkeep" check -j apkeep
run_cmd "version" version
