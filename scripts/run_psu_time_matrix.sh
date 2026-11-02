#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${PROJECT_ROOT}/scripts/common.sh"
BIN="${BIN:-${BUILD_DIR}/psu}"
SETTINGS_FILE="${PSU_SETTINGS_FILE:-${PROJECT_ROOT}/settings.json}"
BUILD_FIRST="${BUILD_FIRST:-1}"
OUT_ROOT="${OUT_ROOT:-${PROJECT_ROOT}/results/net_eval}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
RUN_ROOT="${OUT_ROOT}/${RUN_ID}"
SUMMARY_FILE="${RUN_ROOT}/summary.tsv"
CORE_CSV_FILE="${RUN_ROOT}/core_metrics.csv"
TC_SCENARIOS="${TC_SCENARIOS:-}"
TC_PROFILES="${TC_PROFILES:-}"
PSU_SCENARIOS="${PSU_SCENARIOS:-}"
PSU_PROFILES="${PSU_PROFILES:-}"
MATRIX_SCENARIOS="${PSU_SCENARIOS:-${TC_SCENARIOS}}"
MATRIX_PROFILES="${PSU_PROFILES:-${TC_PROFILES}}"
PSU_LINK_RECV_TIMEOUT_MS="${PSU_LINK_RECV_TIMEOUT_MS:-3600000}"
PSU_LINK_HTTP_TIMEOUT_MS="${PSU_LINK_HTTP_TIMEOUT_MS:-120000}"
PSU_LINK_THROTTLE_WINDOW_SIZE="${PSU_LINK_THROTTLE_WINDOW_SIZE:-2}"
PSU_LINK_CHUNK_PARALLEL_SEND_SIZE="${PSU_LINK_CHUNK_PARALLEL_SEND_SIZE:-1}"

PROFILES=(
  x22_y11
  x22_y12
  x22_y13
  x22_y14
  x24_y11
  x24_y12
  x24_y13
  x24_y14
)

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

filter_profiles() {
  if [[ -z "${MATRIX_PROFILES}" ]]; then
    return 0
  fi
  local selected=()
  local wanted=",${MATRIX_PROFILES},"
  local profile
  for profile in "${PROFILES[@]}"; do
    if [[ "${wanted}" == *",${profile},"* ]]; then
      selected+=("${profile}")
    fi
  done
  PROFILES=("${selected[@]}")
}

scenario_enabled() {
  local scenario="$1"
  if [[ -z "${MATRIX_SCENARIOS}" ]]; then
    return 0
  fi
  local wanted=",${MATRIX_SCENARIOS},"
  [[ "${wanted}" == *",${scenario},"* ]]
}

usage() {
  cat <<'EOF'
Usage:
  run_psu_time_matrix.sh

This script:
1. shapes loopback traffic with tc inside a private network namespace,
2. runs the full distributed PSU benchmark,
3. sweeps X in {2^22, 2^24} and Y in {2^11, 2^12, 2^13, 2^14},
4. records offline time, online time, and total time (= offline + online),
5. stores per-run logs under net_eval/<timestamp>/.

Optional environment overrides:
  RUN_ID=psu_time_sweep
  BUILD_FIRST=0
  PSU_PROFILES=x22_y12,x24_y14
  PSU_SCENARIOS=1mbps_80ms
  OUT_ROOT=net_eval

RTT note:
  The RTT values below are round-trip times.
  Because both parties communicate over loopback on the same host, tc delay
  is configured with one-way delay = RTT / 2.
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

metric_number() {
  local metric="$1"
  if [[ -z "${metric}" ]]; then
    printf '%s\n' ""
    return 0
  fi
  awk '{print $1}' <<< "${metric}"
}

max_metric() {
  local pattern="$1"
  local file_a="$2"
  local file_b="$3"
  local metric_a metric_b num_a num_b
  metric_a="$(extract_metric "${pattern}" "${file_a}")"
  metric_b="$(extract_metric "${pattern}" "${file_b}")"
  if [[ -z "${metric_a}" ]]; then
    printf '%s\n' "${metric_b}"
    return 0
  fi
  if [[ -z "${metric_b}" ]]; then
    printf '%s\n' "${metric_a}"
    return 0
  fi
  num_a="$(metric_number "${metric_a}")"
  num_b="$(metric_number "${metric_b}")"
  if awk -v a="${num_a}" -v b="${num_b}" 'BEGIN { exit((a + 0) >= (b + 0) ? 0 : 1) }'; then
    printf '%s\n' "${metric_a}"
  else
    printf '%s\n' "${metric_b}"
  fi
}

sum_metrics() {
  local metric_a="$1"
  local metric_b="$2"
  local num_a num_b
  num_a="$(metric_number "${metric_a}")"
  num_b="$(metric_number "${metric_b}")"
  awk -v a="${num_a:-0}" -v b="${num_b:-0}" 'BEGIN { printf "%.6f s\n", (a + 0) + (b + 0) }'
}

extract_status() {
  local file_a="$1"
  local file_b="$2"
  if grep -Fq '[CORRECT]' "${file_a}" || grep -Fq '[CORRECT]' "${file_b}"; then
    printf 'CORRECT'
  elif grep -Fq '[WRONG!]' "${file_a}" || grep -Fq '[WRONG!]' "${file_b}"; then
    printf 'WRONG'
  else
    printf 'UNKNOWN'
  fi
}

profile_x_power() {
  local profile="$1"
  printf '%s\n' "${profile%%_*}" | sed 's/^x//'
}

profile_y_power() {
  local profile="$1"
  printf '%s\n' "${profile##*_}" | sed 's/^y//'
}

pow2_value() {
  local exponent="$1"
  awk -v e="${exponent}" 'BEGIN { printf "%.0f\n", 2 ^ e }'
}

mkdir -p "${RUN_ROOT}"

printf "scenario\trate\trtt_ms\tprofile\tnx_pow\tnx\tny_pow\tny\tstatus\toffline_time\tonline_time\ttotal_time\tsetup_prep_time\tend_to_end\treceiver_log\tsender_log\tconsole_log\n" > "${SUMMARY_FILE}"
printf "scenario,rate,rtt_ms,profile,nx_pow,nx,ny_pow,ny,status,offline_time,online_time,total_time\n" > "${CORE_CSV_FILE}"

if [[ "${BUILD_FIRST}" == "1" ]]; then
  build_psu
fi

if [[ ! -x "${BIN}" ]]; then
  echo "binary not found or not executable: ${BIN}" >&2
  exit 1
fi

filter_profiles

if [[ "${#PROFILES[@]}" -eq 0 ]]; then
  echo "no profiles selected" >&2
  exit 1
fi

for idx in "${!SCENARIO_NAMES[@]}"; do
  scenario="${SCENARIO_NAMES[$idx]}"
  if ! scenario_enabled "${scenario}"; then
    continue
  fi
  rate="${SCENARIO_RATES[$idx]}"
  rtt_ms="${SCENARIO_RTT_MS[$idx]}"
  delay="${SCENARIO_DELAY[$idx]}"

  for profile in "${PROFILES[@]}"; do
    run_dir="${RUN_ROOT}/${scenario}/${profile}"
    mkdir -p "${run_dir}"
    console_log="${run_dir}/console.log"
    log_dir="${run_dir}/logs"

    nx_pow="$(profile_x_power "${profile}")"
    ny_pow="$(profile_y_power "${profile}")"
    nx="$(pow2_value "${nx_pow}")"
    ny="$(pow2_value "${ny_pow}")"

    echo "== ${scenario} / ${profile} (|X|=2^${nx_pow}, |Y|=2^${ny_pow}) =="

    unshare --user --map-root-user --net bash -lc "
      set -euo pipefail
      ip link set lo up
      tc qdisc replace dev lo root netem rate '${rate}' delay '${delay}'
      cd '${PROJECT_ROOT}'
      env \
        BUILD_FIRST=0 \
        LOG_DIR='${log_dir}' \
        PSU_LINK_RECV_TIMEOUT_MS='${PSU_LINK_RECV_TIMEOUT_MS}' \
        PSU_LINK_HTTP_TIMEOUT_MS='${PSU_LINK_HTTP_TIMEOUT_MS}' \
        PSU_LINK_THROTTLE_WINDOW_SIZE='${PSU_LINK_THROTTLE_WINDOW_SIZE}' \
        PSU_LINK_CHUNK_PARALLEL_SEND_SIZE='${PSU_LINK_CHUNK_PARALLEL_SEND_SIZE}' \
        PSU_SETTINGS_FILE='${SETTINGS_FILE}' \
        PSU_PROFILE='${profile}' \
        '${SCRIPT_DIR}/run_two_party.sh'
    " |& tee "${console_log}"

    receiver_log="${log_dir}/receiver.log"
    sender_log="${log_dir}/sender.log"

    if [[ ! -f "${receiver_log}" || ! -f "${sender_log}" ]]; then
      echo "missing logs for ${scenario}/${profile}" >&2
      exit 1
    fi

    status="$(extract_status "${receiver_log}" "${sender_log}")"
    setup_prep_time="$(max_metric 'Setup prep time:' "${receiver_log}" "${sender_log}")"
    offline_time="$(max_metric 'Setup time:' "${receiver_log}" "${sender_log}")"
    online_time="$(max_metric 'Online time:' "${receiver_log}" "${sender_log}")"
    total_time="$(sum_metrics "${offline_time}" "${online_time}")"
    end_to_end="$(max_metric 'End-to-end:' "${receiver_log}" "${sender_log}")"

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
      "${scenario}" "${rate}" "${rtt_ms}" "${profile}" \
      "${nx_pow}" "${nx}" "${ny_pow}" "${ny}" "${status}" \
      "${offline_time}" "${online_time}" "${total_time}" \
      "${setup_prep_time}" "${end_to_end}" \
      "${receiver_log}" "${sender_log}" "${console_log}" >> "${SUMMARY_FILE}"

    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
      "${scenario}" "${rate}" "${rtt_ms}" "${profile}" \
      "${nx_pow}" "${nx}" "${ny_pow}" "${ny}" "${status}" \
      "${offline_time}" "${online_time}" "${total_time}" >> "${CORE_CSV_FILE}"
  done
done

echo "all PSU time runs completed"
echo "summary: ${SUMMARY_FILE}"
echo "core metrics: ${CORE_CSV_FILE}"
