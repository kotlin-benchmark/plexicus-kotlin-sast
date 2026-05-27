#!/usr/bin/env bash
# Run the Plexicus SAST Engine against the Kotlin benchmark.
#
# Spring Boot module is scanned with framework=spring-boot and Android with
# framework=android. Both runs produce SARIF artifacts in sast/.
#
# Requirements:
#   - Docker, OR
#   - PLEXICUS_CLI binary on PATH
#   - PLEXICUS_API_KEY exported (or in ~/.plexicus/config)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${REPO_ROOT}/sast/plexicus-rules.yml"
OUT_DIR="${REPO_ROOT}/sast"

mkdir -p "${OUT_DIR}"

if [ -z "${PLEXICUS_API_KEY:-}" ] && [ ! -f "${HOME}/.plexicus/config" ]; then
    echo "WARN: PLEXICUS_API_KEY not set and ~/.plexicus/config not present." >&2
    echo "      The scan will still run if you've already authenticated locally." >&2
fi

run_scan() {
    local module="$1"
    local framework="$2"
    local out="${OUT_DIR}/plexicus-${module}.sarif"

    echo "==> Plexicus SAST — ${module} (framework=${framework})"
    if command -v plexicus >/dev/null 2>&1; then
        plexicus scan \
            --language kotlin \
            --framework "${framework}" \
            --rules "${RULES}" \
            --output "${out}" \
            --sarif \
            "${REPO_ROOT}/${module}"
    elif command -v docker >/dev/null 2>&1; then
        docker run --rm \
            -e PLEXICUS_API_KEY="${PLEXICUS_API_KEY:-}" \
            -v "${REPO_ROOT}:/src:ro" \
            -v "${OUT_DIR}:/out:rw" \
            ghcr.io/plexicus/sast-cli:latest \
            scan \
                --language kotlin \
                --framework "${framework}" \
                --rules "/src/sast/plexicus-rules.yml" \
                --output "/out/plexicus-${module}.sarif" \
                --sarif \
                "/src/${module}"
    else
        echo "ERROR: neither plexicus CLI nor docker is available." >&2
        exit 1
    fi
    echo "==> SARIF written: ${out}"
}

run_scan "spring-app"  "spring-boot"
run_scan "android-app" "android"

echo
echo "==> All Plexicus SAST scans complete."
echo "==> Results:"
echo "    ${OUT_DIR}/plexicus-spring-app.sarif"
echo "    ${OUT_DIR}/plexicus-android-app.sarif"
