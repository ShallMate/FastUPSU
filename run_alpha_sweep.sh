#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
source "${PROJECT_ROOT}/scripts/common.sh"

# Edit this block before running the script.
BIN="${BUILD_DIR}/psu"
SETTINGS_FILE="${SCRIPT_DIR}/settings.json"
BUILD_FIRST=0
OUT_ROOT="${SCRIPT_DIR}/alpha_eval"
RUN_ID="alpha_$(date +%Y%m%d_%H%M%S)"
TRIALS=100
# Upper bound for the polynomial degree. The actual degree may be smaller.
MAX_DEGREE=2048

# Leave ALPHA_INPUTS empty to use ALPHA_PROFILES.
# Leave ALPHA_PROFILES empty to run every profile from settings.json.
ALPHA_PROFILES="x24_y12,x24_y14,x20_y12,x20_y14,x22_y12,x22_y14"

# Custom input format: nx:ny[:label], separated by commas.
# Example:
# ALPHA_INPUTS="1048576:2048:x20_y11_like,4194304:8192:custom_b"
ALPHA_INPUTS=""

RUN_ROOT="${OUT_ROOT}/${RUN_ID}"
SUMMARY_FILE="${RUN_ROOT}/summary.tsv"

if [[ "$#" -ne 0 ]]; then
  echo "this script does not take command-line arguments; edit the config block at the top" >&2
  exit 1
fi

if ! [[ "${TRIALS}" =~ ^[0-9]+$ ]] || [[ "${TRIALS}" == "0" ]]; then
  echo "TRIALS must be a positive integer, got: ${TRIALS}" >&2
  exit 1
fi

safe_name() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9_.-' '_'
}

run_profile() {
  local profile="$1"
  local label="$1"
  local safe_label
  safe_label="$(safe_name "${label}")"
  local run_dir="${RUN_ROOT}/${safe_label}"
  local console_log="${run_dir}/console.log"
  mkdir -p "${run_dir}"

  echo "== alpha / profile=${profile} / trials=${TRIALS} =="
  (
    cd "${PROJECT_ROOT}"
    env \
      PSU_SETTINGS_FILE="${SETTINGS_FILE}" \
      PSU_PROFILE="${profile}" \
      PSU_MODE=alpha-sweep \
      PSU_ALPHA_LABEL="${label}" \
      PSU_ALPHA_TRIALS="${TRIALS}" \
      PSU_ALPHA_OUTPUT="${SUMMARY_FILE}" \
      PSU_MAX_ITEMS_PER_BIN="${MAX_DEGREE}" \
      PSU_USE_DH_OPRF=1 \
      PSU_TRACE=0 \
      stdbuf -oL -eL "${BIN}"
  ) |& tee "${console_log}"
}

run_input() {
  local nx="$1"
  local ny="$2"
  local label="$3"
  local safe_label
  safe_label="$(safe_name "${label}")"
  local run_dir="${RUN_ROOT}/${safe_label}"
  local console_log="${run_dir}/console.log"
  mkdir -p "${run_dir}"

  echo "== alpha / nx=${nx} / ny=${ny} / label=${label} / trials=${TRIALS} =="
  (
    cd "${PROJECT_ROOT}"
    env \
      PSU_SETTINGS_FILE="${SETTINGS_FILE}" \
      PSU_PROFILE=custom \
      PSU_MEDIUM_NX="${nx}" \
      PSU_MEDIUM_NY="${ny}" \
      PSU_MODE=alpha-sweep \
      PSU_ALPHA_LABEL="${label}" \
      PSU_ALPHA_TRIALS="${TRIALS}" \
      PSU_ALPHA_OUTPUT="${SUMMARY_FILE}" \
      PSU_MAX_ITEMS_PER_BIN="${MAX_DEGREE}" \
      PSU_USE_DH_OPRF=1 \
      PSU_TRACE=0 \
      stdbuf -oL -eL "${BIN}"
  ) |& tee "${console_log}"
}

mkdir -p "${RUN_ROOT}"
printf "label\ttrial\tnx\tny\tsimple_hash_bins\tsimple_hash_count\tsigma1_bits\titem_bits\tks\tsigma2_bits\tplain_modulus\talpha_min\tmax_items_per_bin\trequired_alpha\talpha\tmax_bin_size\tsub_bin_size\toprf_alpha_time_s\n" > "${SUMMARY_FILE}"

if [[ "${BUILD_FIRST}" == "1" ]]; then
  build_psu
fi

if [[ ! -x "${BIN}" ]]; then
  echo "binary not found or not executable: ${BIN}" >&2
  exit 1
fi

if [[ -n "${ALPHA_INPUTS}" ]]; then
  IFS=',' read -r -a INPUT_ENTRIES <<< "${ALPHA_INPUTS}"
  for raw_entry in "${INPUT_ENTRIES[@]}"; do
    entry="$(printf '%s' "${raw_entry}" | tr -d '[:space:]')"
    [[ -z "${entry}" ]] && continue
    IFS=':' read -r nx ny label extra <<< "${entry}"
    if [[ -z "${nx:-}" || -z "${ny:-}" || -n "${extra:-}" ]]; then
      echo "invalid ALPHA_INPUTS entry: ${raw_entry}" >&2
      exit 1
    fi
    if ! [[ "${nx}" =~ ^[0-9]+$ && "${ny}" =~ ^[0-9]+$ ]]; then
      echo "ALPHA_INPUTS nx and ny must be integers: ${raw_entry}" >&2
      exit 1
    fi
    if [[ -z "${label:-}" ]]; then
      label="nx${nx}_ny${ny}"
    fi
    run_input "${nx}" "${ny}" "${label}"
  done
else
  if [[ -n "${ALPHA_PROFILES}" ]]; then
    IFS=',' read -r -a PROFILE_LIST <<< "${ALPHA_PROFILES}"
  else
    mapfile -t PROFILE_LIST < <(
      cd "${PROJECT_ROOT}"
      env PSU_SETTINGS_FILE="${SETTINGS_FILE}" PSU_MODE=list-profiles "${BIN}" |
        sed '/^[[:space:]]*$/d'
    )
  fi

  if [[ "${#PROFILE_LIST[@]}" -eq 0 ]]; then
    echo "no profiles selected" >&2
    exit 1
  fi

  for raw_profile in "${PROFILE_LIST[@]}"; do
    profile="$(printf '%s' "${raw_profile}" | tr -d '[:space:]')"
    [[ -z "${profile}" ]] && continue
    run_profile "${profile}"
  done
fi

echo "all alpha runs completed"
echo "summary: ${SUMMARY_FILE}"
