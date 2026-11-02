# FastUPSU

## Install

Ubuntu 22.04+, 16 CPU threads, 64 GB RAM.

```bash
git clone https://github.com/ShallMate/FastUPSU.git
cd FastUPSU
./scripts/install_deps_ubuntu.sh
BUILD_JOBS=8 ./scripts/build.sh
```

## Reproduce

```bash
python3 benchmarks/reproduce.py --output results/paper
```

Results: `results/paper/summary.csv`.
