#!/usr/bin/env bash
# Run checked source regression tests with the exact image's bundled Xray binary.
# All SQLite, Redis-protocol fixtures, TLS certificates and HTTP targets are temporary.
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: container-xray-regression.sh IMAGE TEST_BINARY' >&2; exit 2; }
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == Linux && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || {
  echo 'Use only a disposable GitHub-hosted Linux runner' >&2; exit 1;
}
[[ -z ${DOCKER_HOST:-} || ${DOCKER_HOST} == unix://* ]]
[[ $(docker context inspect --format '{{.Endpoints.docker.Host}}') == unix://* ]]
[[ $(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$1") == linux/amd64 ]]
test_binary=$(realpath "$2")
[[ -f "$test_binary" ]]
# Artifact download does not retain executable bits. Contents were checksum-verified.
chmod 755 "$test_binary"
log=$(mktemp "${RUNNER_TEMP:-/tmp}/xray-image-regression.XXXXXXXX")
trap 'rm -f -- "$log"' EXIT
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --mount "type=bind,source=$test_binary,target=/xray-regression,readonly" \
  --env XRAY_TEST_BINARY=/tpdata/trojan-panel-core/bin/xray/xray \
  --entrypoint /xray-regression "$1" \
  -test.v -test.timeout=120s \
  -test.run '^(TestStableXrayTLSWithPersistedFlow|TestStableXrayRejectsExplicitTrojanFlow|TestValidateXrayUserFlow|TestNormalizeXrayUserFlow)$' | tee "$log"
for name in TestStableXrayTLSWithPersistedFlow TestStableXrayRejectsExplicitTrojanFlow TestValidateXrayUserFlow TestNormalizeXrayUserFlow; do
  grep -F -- "--- PASS: $name " "$log" >/dev/null
 done
printf 'PASS: image-bundled Xray persisted-flow TLS regression (%s)\n' "$1"
