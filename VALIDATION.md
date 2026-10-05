# Validation record — 2026-10-05

## Passed locally

- All six executables built from the pinned official sources for all seven
  original Linux targets: 386, amd64, armv6, armv7, arm64, ppc64le and s390x.
  All 42 outputs were inspected as statically linked ELF executables.
- Native version output identifies Core `v2.3.1-cores.20261005`, Xray `26.3.27`,
  Trojan-Go `v0.10.6`, Hysteria 1 `v1.3.5`, Hysteria 2 `v2.12.3` and Caddy
  `v2.11.7`; Caddy loads the official pinned forwardproxy module.
- Full default Go test suite passes with all five optional real-core binary
  variables enabled. Fixtures use temporary directories, self-signed local test
  certificates, loopback listeners and disposable processes, not deployed data.
- Xray: VMess/VLESS/Trojan/Shadowsocks real HTTP forwarding, add/delete user,
  positive per-user traffic counters, stats reset, system stats and inbound
  removal with the unchanged v1.8.0 panel SDK. Six transport config variants
  validate and eight removed-option cases reject explicitly.
- Hysteria 1: generated config, external HTTP auth payload and real local
  authenticated forwarding with v1.3.5.
- Hysteria 2: generated config, external auth, real local authenticated forwarding
  and per-user traffic read/clear with v2.12.3.
- Trojan-Go: generated server config and real gRPC account, traffic and limit
  lifecycle with v0.10.6.
- Naive: old saved credential migration, real authentication/wrong-password
  rejection, new-user addition and revocation with the Caddy 2.11.7 bundle.
  Fixtures also cover mixed old/current representations and multi-user handlers.
- Migration regression checks: current null vs empty credential list,
  idempotence, unknown fields, permissions, rollback-copy failures, invalid
  existing backup paths and continuing other nodes after a failed migration.
- Xray preflight regression checks: rejected configs stay on disk, include a
  useful diagnostic and do not prevent later valid nodes from starting.
- Focused race-detector checks pass for Naive, Trojan-Go, Hysteria 1 and
  Hysteria 2 with their real binaries enabled.
- `go vet ./...`, shell syntax, CI YAML parsing and `git diff --check` pass.

An independent review identified the per-node startup and backup/null-credential
issues above; regression fixes were added before publication.

## Not established by these checks

- Docker is not installed in this cloud workspace, so the image itself has not
  been built or run locally. CI includes a native Docker packaging check.
- Non-amd64 binaries were cross-compiled and inspected, not run on those CPUs.
- Windows batch wrappers were not executed on Windows.
- No production database/Redis synchronization, quota enforcement, subscription
  client matrix, real certificate/domain deployment or installed server upgrade
  was exercised. Preserve a rollback backup and verify a canary as described in
  [UPGRADE.md](UPGRADE.md).
- No image was published, no live server changed and no installer was executed.

For repeatable commands and environment variables, see [UPGRADE.md](UPGRADE.md).
