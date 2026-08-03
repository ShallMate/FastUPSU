#!/usr/bin/env bash

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BUILD_DIR="${BUILD_DIR:-${PROJECT_ROOT}/build}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
BUILD_JOBS="${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"

build_psu() {
  local generator=()
  if command -v ninja >/dev/null 2>&1; then
    generator=(-G Ninja)
  fi
  cmake -S "${PROJECT_ROOT}" -B "${BUILD_DIR}" \
    "${generator[@]}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
  cmake --build "${BUILD_DIR}" --target psu --parallel "${BUILD_JOBS}"
}
