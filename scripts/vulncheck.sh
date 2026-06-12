#!/usr/bin/env bash
# Run govulncheck and allow known unfixed transitive findings from osv-scalibr
# (docker/moby pulled in via init-time dependency graph, not depx code paths).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

# go run propagates non-zero as its own exit code; parse output instead.
go run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./... >"$out" 2>&1 || true
cat "$out"

if ! grep -q '^Vulnerability #' "$out"; then
	exit 0
fi

# Only these OSV entries are currently allowed: no fixed release exists yet
# (govulncheck reports "Fixed in: N/A") and they come from osv-scalibr → docker.
allowed=(GO-2026-4887 GO-2026-4883)
for id in $(grep -oE 'GO-[0-9-]+' "$out" | sort -u); do
	ok=0
	for allow in "${allowed[@]}"; do
		if [[ "$id" == "$allow" ]]; then
			ok=1
			break
		fi
	done
	if [[ "$ok" -eq 0 ]]; then
		exit 1
	fi
done

echo
echo "govulncheck: ignoring ${allowed[*]} (unfixed transitive osv-scalibr/docker findings)"
exit 0
