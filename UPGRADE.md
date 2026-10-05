# Proxy core upgrade bundle

Verified 2026-10-05 against official stable releases. No prerelease, production
server, database migration, image publication or deployment is part of this patch.

## Versions and evidence

The official installer v2.3.2 release table identifies the previous bundled
binaries. Its `trojan-panel-core` v2.3.1 Go module references Xray v1.8.0 only as
an RPC SDK; the actual previous Xray binary is v1.8.4.

| Component | Previous bundled version | New bundled version | Official source |
| --- | --- | --- | --- |
| Xray binary | v1.8.4 | v26.3.27 | [release](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27), source module tag v1.260327.0 |
| Trojan-Go | v0.10.6 | v0.10.6 (already latest stable) | [release](https://github.com/p4gefau1t/trojan-go/releases/tag/v0.10.6) |
| Hysteria 1 | v1.3.4 | v1.3.5 | [release](https://github.com/HyNetworks/hysteria/releases/tag/v1.3.5) |
| Hysteria 2 | v2.0.4 | v2.12.3 | [release](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.12.3) |
| NaiveProxy server: Caddy | v2.6.4 | v2.11.7 | [release](https://github.com/caddyserver/caddy/releases/tag/v2.11.7) |
| Naive server plugin | unpinned `naive` branch; exact old commit unpublished | v2.11.2-naive, d62c80d3dd2c | [release](https://github.com/klzgrad/forwardproxy/releases/tag/v2.11.2-naive) |

Baseline: [installer version table](https://github.com/trojanpanel/install-script/blob/eee24e804e7d3a4b2c4ec97d59b61cf105b8089e/README_ARCHIVE_ZH.md).
Core source base: `44f674e10deb16f06143c694050f4f1c29427739`.

Naive's Chromium client releases are not the server used by this panel. The
installer's separate frontend Caddy container (2.6.2) is also a different
component and is unchanged. Hysteria 1 remains a separate binary/protocol; it is
not replaced by Hysteria 2.

## Compatibility boundary

- Existing backend 2.3.1 and UI 2.3.0, database schema, account fields, node types,
  REST/gRPC control endpoints, user synchronization and subscription format stay
  unchanged. Only `trojan-panel-core` needs a replacement image.
- Existing binary/config paths, flags, environment variables, volumes, host
  networking, certificate paths and persisted SQLite node metadata are retained.
- The main `go.mod`/`go.sum` RPC dependencies stay unchanged. Runtime binary
  upgrades are real separate source builds, verified by binary version output.
- Latest Xray runs directly, with no legacy fallback and no protocol rewrite.
  Removed options receive the core's explicit preflight error and the saved
  config is retained. Review [Xray migration limits](app/xray/COMPATIBILITY.md).
- Naive keeps the panel's public username/password API shape. Internally it uses
  the new forwardproxy `auth_credentials`. Existing deprecated auth fields are
  converted on startup using an atomic replacement, with the original file
  retained as `<config>.pre-auth-credentials`. Other config fields are preserved.
- Hysteria 1 and Naive already lacked per-user traffic accounting in upstream
  Core 2.3.1. This upgrade does not claim to add that capability or alter quota
  eligibility decisions.

## Reproducible builds

Requirements: Git, Bash, three official Go compilers, and Docker with Buildx for
container packaging. All source refs and peeled commits are pinned in
`scripts/core-versions.env`; source-tree mismatches fail instead of silently
building a different version. Caddy and the forwardproxy replacement have a
separate committed `components/naiveproxy/go.mod` and `go.sum`.

Toolchains are intentionally isolated: panel and Hysteria 1 use Go 1.20.14,
Trojan-Go uses Go 1.17.13, and current Xray/Hysteria 2/Caddy use Go 1.26.8. Old
QUIC/TLS libraries do not compile reliably with modern Go. This is a core-version
upgrade, not a broad dependency/security modernization.

```sh
export GO_PANEL=/path/to/go1.20.14/bin/go
export GO_TROJAN=/path/to/go1.17.13/bin/go
export GO_MODERN=/path/to/go1.26.8/bin/go
scripts/build-components.sh all linux/amd64
scripts/smoke-binaries.sh
```

All original targets remain in the build matrix: linux/386, linux/amd64,
linux/arm/v6, linux/arm/v7, linux/arm64, linux/ppc64le, linux/s390x. Source builds
are required because upstream release assets do not cover every old target.
The old Windows `.bat` entrypoints now forward to the same pinned Bash builder;
Git Bash and the same compiler versions are required.

To build a local image without publishing:

```sh
IMAGE=trojan-panel-core:2.3.1-cores.20261005 ./build.sh
```

Publishing is deliberately opt-in, has no default upstream account, and never
implicitly updates `latest`:

```sh
PUBLISH_IMAGE=YOUR_REGISTRY/trojan-panel-core:2.3.1-cores.20261005 \
PLATFORMS=linux/amd64,linux/arm64 ./build.sh --push
```

The CI matrix builds all six executables for each target, runs native isolated
compatibility tests, checks native container packaging and uploads build
artifacts. It does not publish images or deploy servers. The image includes
`/tpdata/trojan-panel-core/core-versions.env` for runtime inventory.

## Smallest migration for official one-click installations

1. Publish and verify a versioned image in your own registry only after CI and
   a disposable container test pass. Keep the previous image digest.
2. On one canary server, back up `docker inspect trojan-panel-core` and the
   entire `/tpdata/trojan-panel-core/` directory (especially `config/`, SQLite
   state and all `bin/*/config/` directories). Keep the old container/image for
   rollback. Do not overwrite certificates or credentials.
3. Validate every existing Xray JSON using the new binary's
   `xray run -test -config FILE`, with its existing cert paths accessible. Read
   any removed-option errors before changing the running container.
4. Recreate only the core container with the new image, reusing its exact
   existing environment, host network, restart policy and all bind mounts from
   the saved inspect output. Leave the backend, UI, MariaDB, Redis, frontend
   Caddy and their data in place. No schema update or Redis flush is needed.
5. Verify node availability, client authentication, user enable/disable,
   database-to-core synchronization, upload/download accounting for protocols
   which supported it before, quotas, and generated subscriptions on that
   canary before replacing any other server.
6. Roll back by stopping the new core, restoring the backed-up core directory
   (Naive auth JSON changed format), and starting the retained old core image
   with the original configuration.

Do not rerun the unmodified upstream “update core” menu to install this fork: it
pulls `jonssonyan/trojan-panel-core`, can replace the fork with upstream, removes
the old container/image and performs unrelated database/Redis operations.
A fork of the installer, panel backend or UI is not required for the core-only
image replacement described above.

## Verification and limits

Run with Go 1.20.14 (the main module's toolchain):

```sh
XRAY_TEST_BINARY="$PWD/build/xray-linux-amd64" \
NAIVE_TEST_BINARY="$PWD/build/naiveproxy-linux-amd64" \
TROJAN_GO_TEST_BINARY="$PWD/build/trojan-go-linux-amd64" \
HYSTERIA_TEST_BINARY="$PWD/build/hysteria-linux-amd64" \
HYSTERIA2_TEST_BINARY="$PWD/build/hysteria2-linux-amd64" \
"$GO_PANEL" test ./... -count=1
"$GO_PANEL" vet ./...
```

Tests isolate CLI initialization from package imports. Historical fixed-port
external-service tests require the `integration` tag; they are not run against
any production service. The new optional binary tests use temporary files,
ephemeral loopback ports and local proxy traffic.

Local verification and architecture results are recorded in `VALIDATION.md`.
Cross-compilation alone does not establish non-amd64 runtime interoperability.
No live database, production synchronization run, server migration, registry
publication or Docker execution is implied by passing isolated tests.
