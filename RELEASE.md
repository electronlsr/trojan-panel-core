# Versioned container releases

The `Publish versioned containers` workflow builds from reviewed `main` source,
tests the native container against disposable local services, then publishes
seven Linux architectures to `ghcr.io/electronlsr/trojan-panel-core`.

Release tags are explicit in `.release-version` (Core installation release `3.0.0`).
The workflow fails closed on registry uncertainty and refuses to replace an existing version tag and also publishes an
exact `sha-<source-commit>` tag. There is no floating `latest` tag. Consumers
should pin the multi-platform digest recorded in the `release-image` artifact.
The runtime base image is pinned by digest; toolchains and dependency lockfiles
are fixed. SBOM/provenance and OCI source/revision/version labels are included.
The original Alpine/Nginx runtime generation is deliberately retained for
compatibility; this is not a claim that legacy runtimes/dependencies are free of
known vulnerabilities or that all architectures received native execution tests.

Publishing uses only GitHub's per-job `GITHUB_TOKEN` with `packages: write` in
the final publish job. No long-lived token, production secret, or deployment
credential is stored. PRs cannot enter the publish workflow. The workflow runs
on an explicit release-version change on `main` or a manual run
of `main`; tests and cross-compilation must finish first. Repository writers
must bump `.release-version` for each new release.

First publication may create a private GHCR package. Set only this package's
visibility to Public in GitHub's package settings, then verify its manifest and
pull without credentials before distributing an installer. A successful push
alone is not proof of public availability. No server is deployed by this repo.

Runtime paths, environment names, ports, and installer bind-mount conventions
remain unchanged. Native service smoke tests use a new disposable Docker
network, randomized database credentials, and disposable containers only.

Artifacts are verified against per-build SHA-256 checksum manifests after
download. A unique `candidate-<run>-<attempt>` tag is pushed first; only after
pulling that exact digest and passing the native service smoke is the same
index promoted to the version and source-SHA tags. Candidate tags are CI
outputs, not installation releases. Never use them in an installer. Registry
checks and serialized release jobs prevent ordinary accidental replacement;
GHCR tags are not an atomic immutable-tag mechanism, so installers must use
the recorded digest to remain immutable against independent writers.

## 3.0.0 compatibility fix

Core 3.0.0 restores dynamic Trojan user provisioning for legacy node metadata such
as `xray_flow=xtls-rprx-vision`: the old Xray 1.8.4 dynamic Trojan account also
contained only the password, so stale panel metadata is not a Trojan protocol
setting. Stored metadata is preserved; explicit unsupported Trojan flow in
custom JSON remains rejected. VLESS normalizes only the exact `none` UI sentinel
and still rejects genuinely unsupported flows.

The release compiles a static regression test artifact and checks its checksum.
It executes inside both the native build image and the exact pulled candidate
image before version-tag promotion, with no external network or production
state. Coverage includes real TLS certificate validation and HTTP forwarding,
actual AddUser RPCs, reopened SQLite metadata, and an isolated Redis protocol
fixture. The ordinary whole-service MariaDB/Redis/restart smoke remains in place.
UI, backend, Core and the installer are coordinated at 3.0.0. Third-party proxy core versions are unchanged.

## Panel version 3.0.0

Panel runtime/version APIs, the UI package and version file, and the image tag
are now 3.0.0. This release does not rename Xray, Trojan-Go, Hysteria, Caddy or
other third-party components, and it introduces no database schema migration.
