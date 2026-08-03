#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
source "${PROJECT_ROOT}/scripts/common.sh"
BIN="${BIN:-${BUILD_DIR}/psu}"
SETTINGS_FILE="${PSU_SETTINGS_FILE:-${SCRIPT_DIR}/settings.json}"
BUILD_FIRST="${BUILD_FIRST:-0}"
PROFILE_CSV="${PSU_PROFILES:-}"

usage() {
  cat <<'EOF'
Usage:
  prepare_profile_caches.sh

Optional environment overrides:
  BUILD_FIRST=0|1
  BIN=/abs/path/to/psu_binary
  PSU_SETTINGS_FILE=/abs/path/to/settings.json
  PSU_PROFILES=x20_y10,x22_y14
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

declare -a PROFILES=()
if [[ -n "${PROFILE_CSV}" ]]; then
  IFS=',' read -r -a PROFILES <<< "${PROFILE_CSV}"
else
  while IFS= read -r profile; do
    [[ -n "${profile}" ]] && PROFILES+=("${profile}")
  done < <(
    cd "${PROJECT_ROOT}" && \
      env PSU_MODE=list-profiles \
          PSU_SETTINGS_FILE="${SETTINGS_FILE}" \
          "${BIN}"
  )
fi

if [[ "${#PROFILES[@]}" -eq 0 ]]; then
  echo "no profiles configured" >&2
  exit 1
fi

echo "Persistent cache is disabled."
echo "Sender state is prepared in-memory during setup."
exit 1
