# FastUPSU

## Installation

Use Linux x86-64 with a C++20 compiler (GCC 11+), CMake 3.20+, and a CPU supporting AES-NI, PCLMUL, BMI2 and AVX2. The paper runner needs CPU IDs 0–15 and about 64 GiB of RAM for the largest cases.

```bash
git clone https://github.com/ShallMate/FastUPSU.git
cd FastUPSU
./scripts/install_deps_ubuntu.sh
BUILD_JOBS=8 ./build.sh
```

The first build downloads pinned versions of BLAKE3 1.8.2, SEAL 4.1.1, fmt, libOTe, and secure-join. The executable is `build/psu`. BLAKE3 supplies the salted input encoding and the separately domain-separated bin hashes.

To use another build directory:

```bash
BUILD_DIR=build-release BUILD_JOBS=8 ./build.sh
```

## Reproduction

Run from a normal user session with unprivileged user/network namespaces and a running systemd user manager. The runner creates a private network namespace for each case and applies traffic shaping only inside it.

Run all 72 measurements of this protocol: 40 complete PSU cases and 16 cases each for Zero and Perm.

```bash
python3 benchmarks/reproduce.py --output results/paper
```

Run one complete PSU case:

```bash
python3 benchmarks/reproduce.py \
  --mode psu --nx-log 20 --ny-log 12 --network 10Gbps \
  --output results/single
```

Select modules or another network:

```bash
python3 benchmarks/reproduce.py --mode zero --network 1Mbps --output results/zero
python3 benchmarks/reproduce.py --mode perm --network 1Mbps --output results/perm
```

For a different build, add `--binary build-release/psu`. To inspect a plan without running it, add `--plan-only`. Repeating the same command resumes compatible completed cases; an incomplete or failed case stops execution and retains its logs.

The four network profiles are 10 Gbps with 0.05 ms RTT, and 100/10/1 Mbps with 80 ms RTT. Each full-PSU party uses eight offline threads on CPUs 0–7 or 8–15 and one online CPU, 0 or 8. Zero and Perm retain two party workers in one process, with shared online I/O restricted to CPUs 0 and 8. Each case has a 50 GiB memory limit and no swap.

The default input seed is `local-experiment-20261028`; use `--seed` to change it. Inputs are 128-bit elements with an intersection of 128. Each execution samples a fresh encoding salt independently of the input seed.

Results are stored in:

- `plan.json` and `status.json`: selected cases and progress.
- `raw/<case>/`: parameters, commands, network settings, party logs, and the verified result.
- `summary.csv`: offline, online, and total time in seconds; communication in decimal MB (1 MB = 1,000,000 bytes).

The complete PSU results supply Table III and Figure 9. Their S3MT fields supply Table V; `benchmarks/parameters.py` supplies Table IV. Zero and Perm results supply Tables VI and VII. Comparison protocols use their respective authors' artifacts.

To run the focused salted-hash regression:

```bash
cmake --build build --target salted_hash_regression -j8
./build/salted_hash_regression
```
