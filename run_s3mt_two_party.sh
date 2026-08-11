#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
source "${PROJECT_ROOT}/scripts/common.sh"
BIN="${BIN:-${BUILD_DIR}/psu}"
SETTINGS_FILE="${PSU_SETTINGS_FILE:-${SCRIPT_DIR}/settings.json}"
PROFILE="${PSU_PROFILE:-}"
PARTIES="${PSU_PARTIES:-127.0.0.1:9300,127.0.0.1:9301}"
BUILD_FIRST="${BUILD_FIRST:-0}"
LOG_DIR="${LOG_DIR:-${SCRIPT_DIR}/logs}"
RECEIVER_LOG="${LOG_DIR}/receiver.log"
SENDER_LOG="${LOG_DIR}/sender.log"

usage() {
  cat <<'EOF'
Usage:
  run_s3mt_two_party.sh

Runs the S³MT module only:
  sender setup + S³MT online
  without the final EQ-OTE/value transfer stage.

Optional environment overrides:
  BUILD_FIRST=0|1
  BIN=/abs/path/to/psu_binary
  PSU_SETTINGS_FILE=/abs/path/to/settings.json
  PSU_PROFILE=x24_y14
  PSU_PARTIES=127.0.0.1:9300,127.0.0.1:9301
  PSU_ONLINE_THREADS=1
  PSU_MEDIUM_NX=16777216
  PSU_MEDIUM_NY=4096
  PSU_MEDIUM_CAP=128
  PSU_MOD_SWITCH_STEPS=2
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

mkdir -p "${LOG_DIR}"

cleanup() {
  if [[ -n "${RECEIVER_PID:-}" ]] && kill -0 "${RECEIVER_PID}" 2>/dev/null; then
    kill "${RECEIVER_PID}" 2>/dev/null || true
    wait "${RECEIVER_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ "${BUILD_FIRST}" == "1" ]]; then
  build_psu
fi

if [[ ! -x "${BIN}" ]]; then
  echo "binary not found or not executable: ${BIN}" >&2
  exit 1
fi

echo "Starting two-party S³MT run"
echo "  bin:      ${BIN}"
echo "  settings: ${SETTINGS_FILE}"
if [[ -n "${PROFILE}" ]]; then
  echo "  profile:  ${PROFILE}"
fi
echo "  parties:  ${PARTIES}"
echo "  logs:     ${RECEIVER_LOG}, ${SENDER_LOG}"

(
  cd "${PROJECT_ROOT}"
  env \
    PSU_MODE=s3mt-receiver \
    PSU_SETTINGS_FILE="${SETTINGS_FILE}" \
    PSU_PROFILE="${PROFILE}" \
    PSU_PARTIES="${PARTIES}" \
    stdbuf -oL -eL "${BIN}" 2>&1 \
    | tee "${RECEIVER_LOG}" \
    | sed 's/^/[receiver] /'
) &
RECEIVER_PID=$!

sleep 1

set +e
(
  cd "${PROJECT_ROOT}"
  env \
    PSU_MODE=s3mt-sender \
    PSU_SETTINGS_FILE="${SETTINGS_FILE}" \
    PSU_PROFILE="${PROFILE}" \
    PSU_PARTIES="${PARTIES}" \
    stdbuf -oL -eL "${BIN}" 2>&1 \
    | tee "${SENDER_LOG}" \
    | sed 's/^/[sender] /'
)
SENDER_STATUS=$?
wait "${RECEIVER_PID}"
RECEIVER_STATUS=$?
set -e

if [[ "${SENDER_STATUS}" -ne 0 || "${RECEIVER_STATUS}" -ne 0 ]]; then
  echo "two-party S³MT run failed: receiver=${RECEIVER_STATUS}, sender=${SENDER_STATUS}" >&2
  exit 1
fi

echo "two-party S³MT run completed"
