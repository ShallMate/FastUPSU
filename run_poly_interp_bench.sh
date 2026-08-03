#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
source "${PROJECT_ROOT}/scripts/common.sh"

# Edit this block before running the script.
BIN="${BUILD_DIR}/psu"
BUILD_FIRST=1
OUT_ROOT="${SCRIPT_DIR}/interp_eval"
RUN_ID="interp_$(date +%Y%m%d_%H%M%S)"
THREADS=8
JOBS=8
MIN_POINTS=10
MAX_POINTS=1000
POINT_STEP=10
TRIALS=10
WARMUP=1
KS=4
SIGMA2_BITS=15
PLAIN_MODULUS=65537

RUN_ROOT="${OUT_ROOT}/${RUN_ID}"
SUMMARY_FILE="${RUN_ROOT}/summary.csv"
CONSOLE_LOG="${RUN_ROOT}/console.log"

if [[ "$#" -ne 0 ]]; then
  echo "this script does not take command-line arguments; edit the config block at the top" >&2
  exit 1
fi

mkdir -p "${RUN_ROOT}"

if [[ "${BUILD_FIRST}" == "1" ]]; then
  build_psu
fi

if [[ ! -x "${BIN}" ]]; then
  echo "binary not found or not executable: ${BIN}" >&2
  exit 1
fi

echo "== PolyLinks interpolation benchmark =="
echo "threads=${THREADS}, jobs=${JOBS}, points=${MIN_POINTS}..${MAX_POINTS}, trials=${TRIALS}"

(
  cd "${PROJECT_ROOT}"
  env \
    PSU_MODE=poly-interp-bench \
    PSU_THREADS="${THREADS}" \
    PSU_INTERP_JOBS="${JOBS}" \
    PSU_INTERP_MIN_POINTS="${MIN_POINTS}" \
    PSU_INTERP_MAX_POINTS="${MAX_POINTS}" \
    PSU_INTERP_STEP="${POINT_STEP}" \
    PSU_INTERP_TRIALS="${TRIALS}" \
    PSU_INTERP_WARMUP="${WARMUP}" \
    PSU_INTERP_KS="${KS}" \
    PSU_INTERP_SIGMA2_BITS="${SIGMA2_BITS}" \
    PSU_INTERP_PLAIN_MODULUS="${PLAIN_MODULUS}" \
    PSU_INTERP_OUTPUT="${SUMMARY_FILE}" \
    stdbuf -oL -eL "${BIN}"
) |& tee "${CONSOLE_LOG}"

echo "all interpolation benchmark runs completed"
echo "summary: ${SUMMARY_FILE}"
echo "console: ${CONSOLE_LOG}"
