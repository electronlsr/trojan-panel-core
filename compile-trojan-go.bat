@echo off
rem Compatibility entrypoint: use the single pinned build pipeline (Git Bash required).
rem Set GO_PANEL, GO_MODERN, GO_TROJAN to the compiler versions in scripts/core-versions.env.
pushd "%~dp0"
for %%T in (linux/386 linux/amd64 linux/arm/v6 linux/arm/v7 linux/arm64 linux/ppc64le linux/s390x) do (
  bash scripts/build-components.sh trojan-go %%T
  if errorlevel 1 (
    popd
    exit /b 1
  )
)
popd
