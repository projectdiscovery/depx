#!/usr/bin/env bash
set -euo pipefail

go mod tidy

if [[ -n "${GORELEASER_CURRENT_TAG:-}" ]] && [[ -n "${DEPX_PD_API_TOKEN:-}" ]]; then
  echo "building full offline intel bundles for ${GORELEASER_CURRENT_TAG}"
  go run ./cmd/embedintel -out internal/bundle/embedded
elif [[ ! -f internal/bundle/embedded/osv.tar.gz ]] || [[ ! -f internal/bundle/embedded/pd.tar.gz ]]; then
  echo "building minimal embedded stubs"
  go run -tags bootstrap ./cmd/embedintel -minimal -out internal/bundle/embedded
else
  echo "using committed embedded bundles"
fi
