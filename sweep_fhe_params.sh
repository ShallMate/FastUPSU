#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
source "${PROJECT_ROOT}/scripts/common.sh"
BIN="${BIN:-${BUILD_DIR}/psu}"
SETTINGS_FILE="${PSU_SETTINGS_FILE:-${SCRIPT_DIR}/settings.json}"
BUILD_FIRST="${BUILD_FIRST:-0}"
PROFILE_CSV="${PSU_PROFILES:-}"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/results/fhe_sweep}"

usage() {
  cat <<'EOF'
Usage:
  sweep_fhe_params.sh

Optional environment overrides:
  BUILD_FIRST=0|1
  BIN=/abs/path/to/psu_binary
  PSU_SETTINGS_FILE=/abs/path/to/settings.json
  PSU_PROFILES=x20_y10,x22_y14
  OUTPUT_DIR=results/fhe_sweep
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

mkdir -p "${OUTPUT_DIR}"

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

echo "Sweeping FHE parameters for ${#PROFILES[@]} profile(s)"
echo "  settings: ${SETTINGS_FILE}"
echo "  output:   ${OUTPUT_DIR}"

for profile in "${PROFILES[@]}"; do
  echo
  echo "=== fhe-sweep: ${profile} ==="
  (
    cd "${PROJECT_ROOT}"
    env \
      PSU_MODE=fhe-sweep \
      PSU_PROFILE="${profile}" \
      PSU_SETTINGS_FILE="${SETTINGS_FILE}" \
      PSU_FHE_SWEEP_OUTPUT="${OUTPUT_DIR}/${profile}.tsv" \
      stdbuf -oL -eL "${BIN}"
  ) | tee "${OUTPUT_DIR}/${profile}.log"
done
