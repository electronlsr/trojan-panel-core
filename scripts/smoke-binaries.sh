#!/usr/bin/env bash
# Native Linux amd64 smoke checks; no production files or services are touched.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/scripts/core-versions.env"
BIN=${OUTPUT_DIR:-$ROOT/build}
check() {
  local expected=$1
  shift
  local output
  output=$("$@" 2>&1)
  [[ "$output" == *"$expected"* ]] || { echo "Version mismatch for $*: $output" >&2; exit 1; }
  printf '%s\n' "$output"
}
check "v$PANEL_VERSION" "$BIN/trojan-panel-core-linux-amd64" -version
check "${XRAY_VERSION#v}" "$BIN/xray-linux-amd64" version
check "$TROJAN_GO_VERSION" "$BIN/trojan-go-linux-amd64" -version
check "$HYSTERIA1_VERSION" "$BIN/hysteria-linux-amd64" --version
check "${HYSTERIA2_VERSION#app/}" "$BIN/hysteria2-linux-amd64" version
check "$CADDY_VERSION" "$BIN/naiveproxy-linux-amd64" version
check 'http.handlers.forward_proxy' "$BIN/naiveproxy-linux-amd64" list-modules
# All binaries must be statically linked ELF executables for Alpine deployment.
for name in trojan-panel-core xray trojan-go hysteria hysteria2 naiveproxy; do
  file "$BIN/$name-linux-amd64" | grep -q 'ELF .*executable.*statically linked'
done
