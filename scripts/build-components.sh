#!/usr/bin/env bash
# Build pinned official source without publishing or changing installed servers.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/scripts/core-versions.env"
COMPONENT=${1:-all}
TARGET=${2:-linux/amd64}
CACHE_DIR=${CACHE_DIR:-$ROOT/.build-cache}
OUTPUT_DIR=${OUTPUT_DIR:-$ROOT/build}
GO_PANEL=${GO_PANEL:-go}
GO_MODERN=${GO_MODERN:-go}
GO_TROJAN=${GO_TROJAN:-go}
case "$TARGET" in
  linux/386) ARCH=386; ARM=; SUFFIX=linux-386 ;;
  linux/amd64) ARCH=amd64; ARM=; SUFFIX=linux-amd64 ;;
  linux/arm/v6) ARCH=arm; ARM=6; SUFFIX=linux-armv6 ;;
  linux/arm/v7) ARCH=arm; ARM=7; SUFFIX=linux-armv7 ;;
  linux/arm64) ARCH=arm64; ARM=; SUFFIX=linux-arm64 ;;
  linux/ppc64le) ARCH=ppc64le; ARM=; SUFFIX=linux-ppc64le ;;
  linux/s390x) ARCH=s390x; ARM=; SUFFIX=linux-s390x ;;
  *) echo "Unsupported target: $TARGET" >&2; exit 2 ;;
esac
mkdir -p "$CACHE_DIR" "$OUTPUT_DIR"
CACHE_DIR=$(cd "$CACHE_DIR" && pwd)
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)

check_go() {
  local executable=$1 expected=$2 actual
  actual=$("$executable" version)
  [[ "$actual" == "go version go${expected} "* ]] || {
    echo "Expected Go $expected, got '$actual'. Set GO_PANEL, GO_MODERN and GO_TROJAN to the pinned compilers." >&2
    exit 1
  }
}
checkout() {
  local name=$1 repo=$2 ref=$3 commit=$4 path="$CACHE_DIR/$1"
  if [[ ! -d "$path/.git" ]]; then
    git clone --depth 1 --branch "$ref" "https://github.com/$repo.git" "$path"
  fi
  [[ "$(git -C "$path" rev-parse HEAD)" == "$commit" ]] || {
    echo "Source mismatch in $path (expected $commit); use a fresh CACHE_DIR." >&2; exit 1;
  }
  [[ -z "$(git -C "$path" status --porcelain)" ]] || {
    echo "Source has local changes: $path" >&2; exit 1;
  }
}
build_go() {
  local compiler=$1 dir=$2 output=$3
  shift 3
  (cd "$dir" && env CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" GOARM="$ARM" \
    "$compiler" build -mod=readonly -trimpath -o "$OUTPUT_DIR/$output-$SUFFIX" "$@")
}
build_component() {
  case "$1" in
    panel)
      check_go "$GO_PANEL" "$PANEL_GO_VERSION"
      build_go "$GO_PANEL" "$ROOT" trojan-panel-core -ldflags="-s -w -buildid=" .
      ;;
    xray)
      check_go "$GO_MODERN" "$MODERN_GO_VERSION"
      checkout xray XTLS/Xray-core "$XRAY_REF" "$XRAY_COMMIT"
      build_go "$GO_MODERN" "$CACHE_DIR/xray" xray -ldflags="-s -w -buildid=" ./main
      ;;
    trojan-go)
      check_go "$GO_TROJAN" "$TROJAN_GO_TOOLCHAIN_VERSION"
      checkout trojan-go p4gefau1t/trojan-go "$TROJAN_GO_VERSION" "$TROJAN_GO_COMMIT"
      build_go "$GO_TROJAN" "$CACHE_DIR/trojan-go" trojan-go -tags full -ldflags="-s -w -buildid= -X github.com/p4gefau1t/trojan-go/constant.Version=${TROJAN_GO_VERSION} -X github.com/p4gefau1t/trojan-go/constant.Commit=${TROJAN_GO_COMMIT}" .
      ;;
    hysteria)
      check_go "$GO_PANEL" "$PANEL_GO_VERSION"
      checkout hysteria HyNetworks/hysteria "$HYSTERIA1_VERSION" "$HYSTERIA1_COMMIT"
      build_go "$GO_PANEL" "$CACHE_DIR/hysteria/app" hysteria -tags gpl \
        -ldflags="-s -w -buildid= -X main.appVersion=${HYSTERIA1_VERSION} -X main.appCommit=${HYSTERIA1_COMMIT}" ./cmd
      ;;
    hysteria2)
      check_go "$GO_MODERN" "$MODERN_GO_VERSION"
      checkout hysteria2 HyNetworks/hysteria "$HYSTERIA2_VERSION" "$HYSTERIA2_COMMIT"
      build_go "$GO_MODERN" "$CACHE_DIR/hysteria2/app" hysteria2 \
        -ldflags="-s -w -buildid= -X github.com/apernet/hysteria/app/v2/cmd.appVersion=${HYSTERIA2_VERSION#app/} -X github.com/apernet/hysteria/app/v2/cmd.appCommit=${HYSTERIA2_COMMIT}" .
      ;;
    naiveproxy)
      check_go "$GO_MODERN" "$MODERN_GO_VERSION"
      # This isolated module pins Caddy, the official Naive fork and their
      # full dependency graph; the main panel SDK module stays untouched.
      build_go "$GO_MODERN" "$ROOT/components/naiveproxy" naiveproxy -ldflags="-s -w -buildid=" .
      ;;
    *) echo "Unknown component: $1" >&2; exit 2 ;;
  esac
}
if [[ "$COMPONENT" == all ]]; then
  for component in panel xray trojan-go hysteria hysteria2 naiveproxy; do build_component "$component"; done
else
  build_component "$COMPONENT"
fi
# Installed alongside binaries to identify the real bundle, not just panel SDKs.
cp "$ROOT/scripts/core-versions.env" "$OUTPUT_DIR/core-versions.env"
