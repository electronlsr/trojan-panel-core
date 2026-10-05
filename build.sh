#!/usr/bin/env bash
# Local build by default. Publishing requires an explicit flag and destination.
set -euo pipefail
cd "$(dirname "$0")"
source scripts/core-versions.env
PLATFORMS=${PLATFORMS:-linux/amd64}
IMAGE=${IMAGE:-trojan-panel-core:$PANEL_VERSION}
mode=${1:---load}
case "$mode" in
  --load) [[ "$PLATFORMS" != *,* ]] || { echo '--load accepts one platform; use --push or build separately.' >&2; exit 2; } ;;
  --push) [[ -n "${PUBLISH_IMAGE:-}" ]] || { echo 'Set PUBLISH_IMAGE explicitly to publish your own image.' >&2; exit 2; }; IMAGE=$PUBLISH_IMAGE ;;
  *) echo 'Usage: build.sh [--load|--push]' >&2; exit 2 ;;
esac
IFS=, read -r -a targets <<< "$PLATFORMS"
for target in "${targets[@]}"; do scripts/build-components.sh all "$target"; done
docker buildx build --platform "$PLATFORMS" -t "$IMAGE" "$mode" .
