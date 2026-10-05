#!/usr/bin/env bash
# Only an explicit missing manifest permits release. Registry uncertainty fails closed.
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: assert-release-absent.sh IMAGE:TAG' >&2; exit 2; }
ref=$1
if result=$(timeout 60 docker buildx imagetools inspect --raw "$ref" 2>&1); then
  printf 'Release already exists: %s\n' "$ref" >&2
  exit 1
else
  status=$?
fi
if [[ "$status" == 1 && ( "$result" == "ERROR: $ref: not found" || "$result" == "$ref: not found" ) ]]; then
  printf 'Confirmed missing release manifest: %s\n' "$ref"
else
  printf 'Cannot safely determine whether release exists (exit %s):\n%s\n' "$status" "$result" >&2
  exit 1
fi
