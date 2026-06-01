#!/usr/bin/env bash
# Adversarial smoke tests for depx — reports crashes (signals) and unexpected panics.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DEPX_BIN:-$ROOT/bin/depx}"
TMP=$(mktemp -d)
CFG="$TMP/config.yaml"
CACHE="$TMP/cache"
mkdir -p "$CACHE"

cat >"$CFG" <<EOF
cache_dir: $CACHE
feed:
  cache_ttl: 1h
timeout: 5s
EOF

export NO_COLOR=1
BASE=(--disable-update-check --silent --config "$CFG")

PASS=0
FAIL=0
CRASH=0

run_case() {
  local name="$1"
  shift
  local out rc
  out=$(DEPX_OSV_URL="${DEPX_OSV_URL:-https://api.osv.dev/v1}" \
        "$BIN" "${BASE[@]}" "$@" 2>&1) && rc=0 || rc=$?

  if [[ $rc -ge 128 ]]; then
    echo "CRASH  $name (signal $((rc-128)))"
    echo "$out" | tail -5
    CRASH=$((CRASH+1))
    return
  fi
  if echo "$out" | grep -qE 'panic:|runtime error:|fatal error:'; then
    echo "PANIC  $name (exit $rc)"
    echo "$out" | tail -10
    CRASH=$((CRASH+1))
    return
  fi
  echo "OK     $name (exit $rc)"
  PASS=$((PASS+1))
}

echo "=== depx break tests ==="
echo "binary: $BIN"
echo "tmp:    $TMP"
echo

# --- stdin edge cases ---
run_case "empty stdin pipe" bash -c 'echo -n | '"$BIN"' '"${BASE[*]}"''
run_case "blank lines stdin" bash -c 'printf "\n\n  \n#\n" | '"$BIN"' '"${BASE[*]}"''
run_case "10k blank lines" bash -c 'yes "" | head -10000 | '"$BIN"' '"${BASE[*]}"' 2>/dev/null | tail -1'
run_case "10k package refs" bash -c 'yes "lodash" | head -10000 | '"$BIN"' '"${BASE[*]}"' -j 2>/dev/null | tail -3'
run_case "null byte in ref" bash -c 'printf "foo\x00bar\n" | '"$BIN"' '"${BASE[*]}"''
run_case "unicode ref" bash -c 'printf "пакет\n🎭pkg\n" | '"$BIN"' '"${BASE[*]}"''
run_case "very long ref 64k" bash -c 'python3 -c "print(\"a\"*65536)" | '"$BIN"' '"${BASE[*]}"''
run_case "shell metachars" bash -c 'printf "\$(rm -rf /)\n; DROP TABLE;\n" | '"$BIN"' '"${BASE[*]}"''

# --- advisory / ref confusion ---
run_case "fake MAL id" bash -c 'echo MAL-9999-999999 | '"$BIN"' '"${BASE[*]}"''
run_case "GHSA malformed" bash -c 'echo GHSA-not-valid | '"$BIN"' '"${BASE[*]}"''
run_case "mix package and MAL id" bash -c 'printf "lodash\nMAL-2026-3431\n" | '"$BIN"' '"${BASE[*]}"' -j'
run_case "CVE only" bash -c 'echo CVE-2024-00001 | '"$BIN"' '"${BASE[*]}"''

# --- flag abuse ---
run_case "invalid since" bash -c '"$BIN" '"${BASE[*]}"' --since not-a-duration -n 1'
run_case "negative limit" bash -c '"$BIN" '"${BASE[*]}"' -n -1'
run_case "huge limit" bash -c '"$BIN" '"${BASE[*]}"' -n 999999999 -j'
run_case "zero timeout" bash -c '"$BIN" '"${BASE[*]}"' --timeout 0 lodash -j'
run_case "unknown ecosystem" bash -c '"$BIN" '"${BASE[*]}"' -e notreal foo -j'
run_case "double subcommand" bash -c '"$BIN" '"${BASE[*]}"' audit audit lodash -j'

# --- audit path abuse ---
run_case "audit /dev/null" bash -c '"$BIN" '"${BASE[*]}"' audit /dev/null -j'
run_case "audit missing path" bash -c '"$BIN" '"${BASE[*]}"' audit /no/such/path/depx-test -j'
run_case "audit empty file as sbom" bash -c 'f='"$TMP"'/empty.json; : >"$f"; '"$BIN"' '"${BASE[*]}"' audit "$f" -j'
run_case "audit garbage json" bash -c 'f='"$TMP"'/bad.cdx.json; echo "{not json" >"$f"; '"$BIN"' '"${BASE[*]}"' audit "$f" -j'
run_case "audit huge path string" bash -c 'f='"$TMP"'/x; python3 -c "print(\"a\"*8000)" >"$f"; '"$BIN"' '"${BASE[*]}"' audit "$f" -j'
run_case "audit symlink to root" bash -c 'ln -sf / '"$TMP"'/rootlink 2>/dev/null; '"$BIN"' '"${BASE[*]}"' audit '"$TMP"'/rootlink -j 2>/dev/null | tail -1'

# --- config abuse ---
BAD_CFG="$TMP/bad.yaml"
echo "cache_dir: [$CACHE" >"$BAD_CFG"
run_case "broken yaml config" bash -c '"$BIN" --disable-update-check --silent --config "'"$BAD_CFG"'" lodash -j'
echo "cache_dir: /proc/self/noexist" >"$BAD_CFG"
run_case "unwritable cache path" bash -c '"$BIN" --disable-update-check --silent --config "'"$BAD_CFG"'" -n 1 -j'

# --- id command ---
run_case "id empty string" bash -c '"$BIN" '"${BASE[*]}"' id ""'
run_case "id with spaces" bash -c '"$BIN" '"${BASE[*]}"' id "MAL 2026 3431"'
run_case "id path traversal" bash -c '"$BIN" '"${BASE[*]}"' id "../../../etc/passwd"'

# --- explicit refs ---
run_case "npm empty name" bash -c 'echo "npm:" | '"$BIN"' '"${BASE[*]}"''
run_case "pypi version only" bash -c 'echo "pypi::@1.0.0" | '"$BIN"' '"${BASE[*]}"''
run_case "pkg purl malformed" bash -c 'echo "pkg:noslash" | '"$BIN"' '"${BASE[*]}"''
run_case "multiple @ in ref" bash -c 'echo "npm:foo@bar@baz" | '"$BIN"' '"${BASE[*]}"''

# --- concurrent hammer (same cache) ---
run_case "20 parallel checks" bash -c '
  for i in $(seq 1 20); do
    echo "lodash" | '"$BIN"' '"${BASE[*]}"' -j >/dev/null &
  done
  wait
'

# --- fixture audits ---
run_case "audit clean project" bash -c '"$BIN" '"${BASE[*]}"' audit "'"$ROOT"'/testdata/fixtures/clean-project" -j'
run_case "audit cyclonedx fixture" bash -c '"$BIN" '"${BASE[*]}"' audit "'"$ROOT"'/testdata/fixtures/clean-sbom/bom.cdx.json" -j'

# --- github command (parse / usage; no live GitHub API) ---
run_case "github no args" bash -c '"$BIN" '"${BASE[*]}"' github'
run_case "github empty target" bash -c '"$BIN" '"${BASE[*]}"' github ""'
run_case "github invalid target" bash -c '"$BIN" '"${BASE[*]}"' github "!!!invalid!!!"'
run_case "github non-github url" bash -c '"$BIN" '"${BASE[*]}"' github "https://example.com/acme/repo"'
run_case "github path traversal" bash -c '"$BIN" '"${BASE[*]}"' github "../../../etc/passwd"'
run_case "github negative limit" bash -c '"$BIN" '"${BASE[*]}"' github -n -1 breakorg'
run_case "github excessive limit" bash -c '"$BIN" '"${BASE[*]}"' github -n 999999999 breakorg'
run_case "github shell metachars" bash -c '"$BIN" '"${BASE[*]}"' github "$(rm -rf /)"'
run_case "github unicode org" bash -c '"$BIN" '"${BASE[*]}"' github "пакет"'

echo
echo "=== summary ==="
echo "ok:     $PASS"
echo "crash:  $CRASH"
echo "tmp:    $TMP (kept for inspection)"

if [[ $CRASH -gt 0 ]]; then exit 1; fi
