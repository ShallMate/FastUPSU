# UPSU

Standalone CMake implementation of the two-party UPSU protocol. The source,
build system, runtime settings, and experiment scripts in this directory do
not depend on an external monorepo.

## Platform

- Ubuntu 20.04 or newer on x86-64
- GCC 10+ or Clang 12+
- CPU support for AES-NI, PCLMUL, BMI2, SSE4.1, AVX, and AVX2
- Git network access during the first configure (pinned third-party sources are
  downloaded by CMake)

Install system packages:

```bash
./scripts/install_deps_ubuntu.sh
```

## Build

```bash
./build.sh
```

The executable is written to `build/psu`. To use a different build directory:

```bash
BUILD_DIR=/tmp/upsu-build BUILD_JOBS=8 ./build.sh
```

## Verify with a real two-party run

The smoke command starts both parties over TCP, runs the complete protocol on
small synthetic sets, and verifies the recovered union:

```bash
./run_smoke.sh
```

Logs are written to `logs/smoke/receiver.log` and
`logs/smoke/sender.log`. Ports can be overridden with `PSU_PARTIES`,
`PSU_PERM_ADDRESS`, `PSU_OTE_ADDRESS`, and `PSU_PEQT_ADDRESS`.

## Run a configured profile

```bash
PSU_PROFILE=x20_y11 BUILD_FIRST=0 ./run_two_party.sh
```

List all profiles:

```bash
PSU_MODE=list-profiles PSU_SETTINGS_FILE="$PWD/settings.json" ./build/psu
```

All other `run_*.sh`, `prepare_*.sh`, and `sweep_*.sh` scripts use the same
CMake binary. Run a script with `--help` for its environment overrides.
