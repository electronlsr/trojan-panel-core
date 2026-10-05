# Versioned container releases

The `Publish versioned containers` workflow builds from reviewed `main` source,
tests the native container against disposable local services, then publishes
seven Linux architectures to `ghcr.io/electronlsr/trojan-panel-core`.

Release tags are explicit in `.release-version` (initial release `2026.10.05`).
The workflow refuses to replace an existing version tag and also publishes an
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
on an explicit release-version/build recipe change on `main` or a manual run
of `main`; tests and cross-compilation must finish first. Repository writers
must bump `.release-version` for each new release.

First publication may create a private GHCR package. Set only this package's
visibility to Public in GitHub's package settings, then verify its manifest and
pull without credentials before distributing an installer. A successful push
alone is not proof of public availability. No server is deployed by this repo.

Runtime paths, environment names, ports, and installer bind-mount conventions
remain unchanged. Native service smoke tests use a new disposable Docker
network, randomized database credentials, and disposable containers only.
