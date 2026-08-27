#!/usr/bin/env bash
# Run govulncheck and allow the known unfixed OpenPGP finding.
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

# OpenPGP is reached through the existing self-update implementation. The
# vulnerability database reports no fixed release.
allowed=(
	GO-2026-5932 # x/crypto openpgp (unmaintained)
)
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
echo "govulncheck: ignoring ${allowed[*]} (unfixed OpenPGP finding)"
exit 0
