#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
source "${PROJECT_ROOT}/scripts/common.sh"
BIN="${BIN:-${BUILD_DIR}/psu}"
BUILD_FIRST="${BUILD_FIRST:-1}"
OUT_ROOT="${OUT_ROOT:-${SCRIPT_DIR}/net_eval}"
RUN_ID="${RUN_ID:-packed_zero_test_$(date +%Y%m%d_%H%M%S)}"
RUN_ROOT="${OUT_ROOT}/${RUN_ID}"
SUMMARY_FILE="${RUN_ROOT}/summary.tsv"
CORE_CSV_FILE="${RUN_ROOT}/core_metrics.csv"
N_POWERS_CSV="${N_POWERS_CSV:-11,12,13,14}"
PACKED_ZERO_BITS="${PSU_PACKED_ZERO_BITS:-48}"
TC_SCENARIOS="${TC_SCENARIOS:-}"

SCENARIO_NAMES=(
  10gbps_0p05ms
  100mbps_80ms
  10mbps_80ms
  1mbps_80ms
)
SCENARIO_RATES=(
  10gbit
  100mbit
  10mbit
  1mbit
)
SCENARIO_RTT_MS=(
  0.05
  80
  80
  80
)
SCENARIO_DELAY=(
  25us
  40ms
  40ms
  40ms
)

usage() {
  cat <<'EOF'
Usage:
  run_packed_zero_test_matrix.sh

This script benchmarks the packed zero-test primitive only.
It does not run PSU sender setup, table building, or Polynomial Links.

Default sweep:
  scenarios in {10gbps_0p05ms, 100mbps_80ms, 10mbps_80ms, 1mbps_80ms}
  n in {2^11, 2^12, 2^13, 2^14}

Optional environment overrides:
  BUILD_FIRST=0
  BIN=/abs/path/to/psu
  OUT_ROOT=net_eval
  RUN_ID=packed_zero_try1
  TC_SCENARIOS=10mbps_80ms,1mbps_80ms
  N_POWERS_CSV=11,12,13,14
  PSU_PACKED_ZERO_BITS=48
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

extract_metric() {
  local pattern="$1"
  local file="$2"
  local line
  line="$(grep -F "  ${pattern}" "${file}" | tail -n 1 || true)"
  line="${line#  ${pattern}}"
  line="${line#"${line%%[![:space:]]*}"}"
  printf '%s\n' "${line}"
}

extract_status() {
  local file="$1"
  if grep -Fq 'Correct:           yes' "${file}"; then
    printf 'CORRECT'
  elif grep -Fq 'Correct:           no' "${file}"; then
    printf 'WRONG'
  else
    printf 'UNKNOWN'
  fi
}

scenario_enabled() {
  local scenario="$1"
  if [[ -z "${TC_SCENARIOS}" ]]; then
    return 0
  fi
  local wanted=",${TC_SCENARIOS},"
  [[ "${wanted}" == *",${scenario},"* ]]
}

pow2_value() {
  local exponent="$1"
  awk -v e="${exponent}" 'BEGIN { printf "%.0f\n", 2 ^ e }'
}

mkdir -p "${RUN_ROOT}"

printf "scenario\trate\trtt_ms\tn_pow\tn\tbit_width\tstatus\tsetup_time\tonline_time\tsetup_comm\tonline_comm\ttotal_comm\toutput_ones\tconsole_log\n" > "${SUMMARY_FILE}"
printf "scenario,rate,rtt_ms,n_pow,n,bit_width,status,setup_time,online_time,setup_comm,online_comm,total_comm\n" > "${CORE_CSV_FILE}"

if [[ "${BUILD_FIRST}" == "1" ]]; then
  build_psu
fi

if [[ ! -x "${BIN}" ]]; then
  echo "binary not found or not executable: ${BIN}" >&2
  exit 1
fi

IFS=',' read -r -a N_POWERS <<< "${N_POWERS_CSV}"

for idx in "${!SCENARIO_NAMES[@]}"; do
  scenario="${SCENARIO_NAMES[$idx]}"
  if ! scenario_enabled "${scenario}"; then
    continue
  fi
  rate="${SCENARIO_RATES[$idx]}"
  rtt_ms="${SCENARIO_RTT_MS[$idx]}"
  delay="${SCENARIO_DELAY[$idx]}"

  for raw_pow in "${N_POWERS[@]}"; do
    n_pow="$(printf '%s' "${raw_pow}" | tr -d '[:space:]')"
    n="$(pow2_value "${n_pow}")"
    run_dir="${RUN_ROOT}/${scenario}/n${n_pow}"
    mkdir -p "${run_dir}"
    console_log="${run_dir}/console.log"

    echo "== packed zero test / ${scenario} / n=2^${n_pow} (${n}) =="

    unshare --user --map-root-user --net bash -lc "
      set -euo pipefail
      ip link set lo up
      tc qdisc replace dev lo root netem rate '${rate}' delay '${delay}'
      cd '${PROJECT_ROOT}'
      env \
        PSU_MODE=packed-zero-bench \
        PSU_PRIMITIVE_N='${n}' \
        PSU_PACKED_ZERO_BITS='${PACKED_ZERO_BITS}' \
        stdbuf -oL -eL '${BIN}'
    " |& tee "${console_log}"

    status="$(extract_status "${console_log}")"
    setup_time="$(extract_metric 'Setup time:' "${console_log}")"
    online_time="$(extract_metric 'Online time:' "${console_log}")"
    setup_comm="$(extract_metric 'Setup comm:' "${console_log}")"
    online_comm="$(extract_metric 'Online comm:' "${console_log}")"
    total_comm="$(extract_metric 'Total comm (S↔R):' "${console_log}")"
    output_ones="$(extract_metric 'Output ones:' "${console_log}")"

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
      "${scenario}" "${rate}" "${rtt_ms}" "${n_pow}" "${n}" \
      "${PACKED_ZERO_BITS}" "${status}" "${setup_time}" "${online_time}" \
      "${setup_comm}" "${online_comm}" "${total_comm}" "${output_ones}" \
      "${console_log}" >> "${SUMMARY_FILE}"

    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
      "${scenario}" "${rate}" "${rtt_ms}" "${n_pow}" "${n}" \
      "${PACKED_ZERO_BITS}" "${status}" "${setup_time}" "${online_time}" \
      "${setup_comm}" "${online_comm}" "${total_comm}" >> "${CORE_CSV_FILE}"
  done
done

echo "all packed zero-test runs completed"
echo "summary: ${SUMMARY_FILE}"
echo "core metrics: ${CORE_CSV_FILE}"
