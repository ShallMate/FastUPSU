#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
source "${PROJECT_ROOT}/scripts/common.sh"
BIN="${BIN:-${BUILD_DIR}/psu}"
SETTINGS_FILE="${PSU_SETTINGS_FILE:-${SCRIPT_DIR}/settings.json}"
PROFILE="${PSU_PROFILE:-}"
BUILD_FIRST="${BUILD_FIRST:-0}"

usage() {
  cat <<'EOF'
Usage:
  prepare_cache.sh

Optional environment overrides:
  BUILD_FIRST=0|1
  BIN=/abs/path/to/psu_binary
  PSU_SETTINGS_FILE=/abs/path/to/settings.json
  PSU_PROFILE=x24_y12
  PSU_CACHE_TAG=pm4096_try1
  PSU_OFFLINE_THREADS=8
  PSU_MEDIUM_NX=16777216
  PSU_MEDIUM_NY=4096
  PSU_MEDIUM_CAP=128
  PSU_PREPARED_CACHE_FILE=cache/x24_y12/pm4096_try1/prepared_sender.bin
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${BUILD_FIRST}" == "1" ]]; then
  build_psu
fi

if [[ ! -x "${BIN}" ]]; then
  echo "binary not found or not executable: ${BIN}" >&2
  exit 1
fi

echo "Persistent cache is disabled."
echo "Sender state is prepared in-memory during setup."
exit 1
