#!/usr/bin/env bash
# Run Microsoft DevSkim against the Plexicus Kotlin benchmark.
#
# Produces SARIF 2.1.0 covering BOTH spring-app/ and android-app/ in a single
# scan and writes the result to sast/devskim-results.sarif so it can be opened
# in any SARIF viewer (Sarif Explorer, VS Code SARIF Viewer, GitHub Code
# Scanning).
#
# Requirements:
#   - Docker (preferred), OR
#   - dotnet tool install --global Microsoft.CST.DevSkim.CLI
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${REPO_ROOT}/sast/devskim-results.sarif"

mkdir -p "${REPO_ROOT}/sast"

echo "==> Running DevSkim against:"
echo "    spring-app/"
echo "    android-app/"
echo "==> Output: ${OUT}"

if command -v docker >/dev/null 2>&1; then
    docker run --rm \
        -v "${REPO_ROOT}:/src:ro" \
        -v "${REPO_ROOT}/sast:/out:rw" \
        ghcr.io/microsoft/devskim:latest \
        analyze \
            -I /src/spring-app -I /src/android-app \
            -O /out/devskim-results.sarif \
            -f sarif
elif command -v devskim >/dev/null 2>&1; then
    devskim analyze \
        -I "${REPO_ROOT}/spring-app" \
        -I "${REPO_ROOT}/android-app" \
        -O "${OUT}" \
        -f sarif
else
    echo "ERROR: neither docker nor the devskim CLI was found." >&2
    echo "Install one of:" >&2
    echo "  - Docker Desktop / engine" >&2
    echo "  - dotnet tool install --global Microsoft.CST.DevSkim.CLI" >&2
    exit 1
fi

echo "==> DevSkim run complete."
echo "==> SARIF results at: ${OUT}"
