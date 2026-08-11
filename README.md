# Online-Efficient Unbalanced Private Set Union with Low Communication

## Requirements

- Ubuntu 20.04+ on x86-64
- GCC 10+ or Clang 12+
- AES-NI, PCLMUL, BMI2, SSE4.1, AVX and AVX2
- Git network access for the first build

Install system dependencies:

```bash
./scripts/install_deps_ubuntu.sh
```

## Build

```bash
./build.sh
```

The binary is generated at `build/psu`.

```bash
BUILD_DIR=/tmp/upsu-build BUILD_JOBS=8 ./build.sh
```

## Run

Small two-party smoke test:

```bash
./run_smoke.sh
```

Run a configured profile:

```bash
PSU_PROFILE=x20_y11 BUILD_FIRST=0 ./run_two_party.sh
```

List profiles:

```bash
PSU_MODE=list-profiles PSU_SETTINGS_FILE="$PWD/settings.json" ./build/psu
```

Runtime parameters are in `settings.json`. Environment variables can override
the corresponding settings.

Logs are written to `logs/smoke/` for the smoke test and `logs/` for regular
two-party runs.

## Experiments

```bash
./run_psu_time_matrix.sh
./run_tc_matrix.sh
./run_s3mt_time_matrix.sh
./run_s3mt_tc_matrix.sh
./run_packed_zero_test_matrix.sh
./run_online_permutation_matrix.sh
./run_poly_interp_bench.sh
./run_alpha_sweep.sh
./sweep_fhe_params.sh
```
