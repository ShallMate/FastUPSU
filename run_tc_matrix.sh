#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
source "${PROJECT_ROOT}/scripts/common.sh"
BIN="${BIN:-${BUILD_DIR}/psu}"
SETTINGS_FILE="${PSU_SETTINGS_FILE:-${SCRIPT_DIR}/settings.json}"
BUILD_FIRST="${BUILD_FIRST:-1}"
OUT_ROOT="${OUT_ROOT:-${SCRIPT_DIR}/net_eval}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
RUN_ROOT="${OUT_ROOT}/${RUN_ID}"
SUMMARY_FILE="${RUN_ROOT}/summary.tsv"
CORE_CSV_FILE="${RUN_ROOT}/core_metrics.csv"
RESUME="${RESUME:-0}"
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
  x20_y11
  x20_y12
  x20_y13
  x20_y14
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
  run_tc_matrix.sh

This script:
1. shapes loopback traffic with tc,
2. runs all x24/x22/x20 profiles,
3. stores per-run logs under net_eval/<timestamp>/,
4. writes a summary TSV.

RTT note:
  The RTT values below are round-trip times.
  Because both parties communicate over loopback on the same host, tc delay
  is configured with one-way delay = RTT / 2.

Environment overrides:
  BIN=/abs/path/to/psu
  PSU_SETTINGS_FILE=/abs/path/to/settings.json
  BUILD_FIRST=0|1
  OUT_ROOT=net_eval
  RUN_ID=custom_name
  RESUME=0|1

The default scenarios are:
  10gbps_0p05ms  -> 10 Gbps, 0.05 ms RTT
  100mbps_80ms   -> 100 Mbps, 80 ms RTT
  10mbps_80ms    -> 10 Mbps, 80 ms RTT
  1mbps_80ms     -> 1 Mbps, 80 ms RTT

This script uses unshare + tc inside a private network namespace.

Optional matrix filters:
  PSU_SCENARIOS=1mbps_80ms
  PSU_PROFILES=x24_y11,x24_y12
  # backward-compatible aliases:
  TC_SCENARIOS=1mbps_80ms
  TC_PROFILES=x24_y11,x24_y12

Low-bandwidth BRPC tuning defaults used by this script:
  PSU_LINK_RECV_TIMEOUT_MS=3600000
  PSU_LINK_HTTP_TIMEOUT_MS=120000
  PSU_LINK_THROTTLE_WINDOW_SIZE=2
  PSU_LINK_CHUNK_PARALLEL_SEND_SIZE=1

Resume mode:
  RESUME=1 RUN_ID=existing_run_id run_tc_matrix.sh

  Resume mode keeps existing summary files, skips cases already marked CORRECT,
  and rewrites the summary row for a case if that case is rerun.

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

extract_status() {
  local file="$1"
  if grep -Fq '[CORRECT]' "${file}"; then
    printf 'CORRECT'
  elif grep -Fq '[WRONG!]' "${file}"; then
    printf 'WRONG'
  else
    printf 'UNKNOWN'
  fi
}

SUMMARY_HEADER="scenario	rate	rtt_ms	profile	status	setup_time	perm_setup_time	peqt_time	perm_online_time	online_time	online_wall	end_to_end	setup_comm	perm_setup_comm	peqt_comm	ote_comm	perm_online_comm	fhe_qr_comm	online_comm	total_comm	receiver_log	sender_log	console_log"
CORE_CSV_HEADER="scenario,rate,rtt_ms,profile,status,setup_time,setup_comm,online_time,online_comm"

init_output_files() {
  mkdir -p "${RUN_ROOT}"

  if [[ "${RESUME}" == "1" ]]; then
    if [[ ! -s "${SUMMARY_FILE}" ]]; then
      printf "%s\n" "${SUMMARY_HEADER}" > "${SUMMARY_FILE}"
    fi
    if [[ ! -s "${CORE_CSV_FILE}" ]]; then
      printf "%s\n" "${CORE_CSV_HEADER}" > "${CORE_CSV_FILE}"
    fi
    echo "resume enabled: ${RUN_ROOT}"
    return 0
  fi

  printf "%s\n" "${SUMMARY_HEADER}" > "${SUMMARY_FILE}"
  printf "%s\n" "${CORE_CSV_HEADER}" > "${CORE_CSV_FILE}"
}

case_completed() {
  local scenario="$1"
  local profile="$2"
  if [[ "${RESUME}" != "1" || ! -f "${SUMMARY_FILE}" ]]; then
    return 1
  fi
  awk -F '\t' -v scenario="${scenario}" -v profile="${profile}" '
    NR > 1 && $1 == scenario && $4 == profile && $5 == "CORRECT" {
      found = 1
    }
    END {
      exit(found ? 0 : 1)
    }
  ' "${SUMMARY_FILE}"
}

drop_existing_case_rows() {
  local scenario="$1"
  local profile="$2"
  local summary_tmp="${SUMMARY_FILE}.tmp"
  local core_tmp="${CORE_CSV_FILE}.tmp"

  awk -F '\t' -v OFS='\t' -v scenario="${scenario}" -v profile="${profile}" '
    NR == 1 || !($1 == scenario && $4 == profile)
  ' "${SUMMARY_FILE}" > "${summary_tmp}"
  mv "${summary_tmp}" "${SUMMARY_FILE}"

  awk -F ',' -v OFS=',' -v scenario="${scenario}" -v profile="${profile}" '
    NR == 1 || !($1 == scenario && $4 == profile)
  ' "${CORE_CSV_FILE}" > "${core_tmp}"
  mv "${core_tmp}" "${CORE_CSV_FILE}"
}

init_output_files

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

    echo "== ${scenario} / ${profile} =="
    if case_completed "${scenario}" "${profile}"; then
      echo "skip completed case: ${scenario} / ${profile}"
      continue
    fi

    unshare --user --map-root-user --net bash -lc "
      set -euo pipefail
      ip link set lo up
      tc qdisc replace dev lo root netem rate '${rate}' delay '${delay}'
      cd '${PROJECT_ROOT}'
      env \
        BUILD_FIRST=0 \
        LOG_DIR='${log_dir}' \
        PSU_TRACE='${PSU_TRACE:-0}' \
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

    receiver_status="$(extract_status "${receiver_log}")"
    if [[ "${receiver_status}" == "CORRECT" ]]; then
      status="CORRECT"
    elif [[ "${receiver_status}" == "WRONG" ]]; then
      status="WRONG"
    else
      status="UNKNOWN"
    fi

    setup_time="$(max_metric 'Setup time:' "${receiver_log}" "${sender_log}")"
    perm_setup_time="$(max_metric 'Perm setup time:' "${receiver_log}" "${sender_log}")"
    peqt_time="$(max_metric 'PEQT time:' "${receiver_log}" "${sender_log}")"
    perm_online_time="$(max_metric 'Perm online time:' "${receiver_log}" "${sender_log}")"
    online_time="$(max_metric 'Online time:' "${receiver_log}" "${sender_log}")"
    online_wall="$(max_metric 'Online wall:' "${receiver_log}" "${sender_log}")"
    end_to_end="$(max_metric 'End-to-end:' "${receiver_log}" "${sender_log}")"
    setup_comm="$(max_metric 'Setup comm:' "${receiver_log}" "${sender_log}")"
    perm_setup_comm="$(max_metric 'Perm setup comm:' "${receiver_log}" "${sender_log}")"
    peqt_comm="$(max_metric 'PEQT comm:' "${receiver_log}" "${sender_log}")"
    ote_comm="$(max_metric 'OTE comm:' "${receiver_log}" "${sender_log}")"
    perm_online_comm="$(max_metric 'Perm online comm:' "${receiver_log}" "${sender_log}")"
    fhe_qr_comm="$(max_metric 'FHE q/r comm:' "${receiver_log}" "${sender_log}")"
    online_comm="$(max_metric 'Online comm:' "${receiver_log}" "${sender_log}")"
    total_comm="$(max_metric 'Total comm (S↔R):' "${receiver_log}" "${sender_log}")"

    drop_existing_case_rows "${scenario}" "${profile}"

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
      "${scenario}" "${rate}" "${rtt_ms}" "${profile}" "${status}" \
      "${setup_time}" "${perm_setup_time}" "${peqt_time}" "${perm_online_time}" \
      "${online_time}" "${online_wall}" "${end_to_end}" "${setup_comm}" \
      "${perm_setup_comm}" "${peqt_comm}" "${ote_comm}" "${perm_online_comm}" \
      "${fhe_qr_comm}" "${online_comm}" "${total_comm}" \
      "${receiver_log}" "${sender_log}" "${console_log}" >> "${SUMMARY_FILE}"

    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
      "${scenario}" "${rate}" "${rtt_ms}" "${profile}" "${status}" \
      "${setup_time}" "${setup_comm}" "${online_time}" "${online_comm}" \
      >> "${CORE_CSV_FILE}"
  done
done

echo "all runs completed"
echo "summary: ${SUMMARY_FILE}"
echo "core metrics: ${CORE_CSV_FILE}"
