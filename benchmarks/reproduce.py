#!/usr/bin/env python3
"""Reproduce the paper's 40 PSU and 32 primitive cases sequentially."""
import argparse
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from export_results import export_results
from network import PROFILES

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REVISION = 'paper-20261102-salted-blake3-v1'
PAIRS = [(20,12),(24,14),(20,14),(22,12),(22,14),(24,12),
         (22,11),(22,13),(24,11),(24,13)]


def write(path, data):
    temporary = path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(data, indent=2)+'\n')
    temporary.replace(path)


def jobs(args):
    rows = []
    for network in args.network:
        if args.mode in ('all', 'psu'):
            for nx, ny in PAIRS:
                if (args.nx_log and nx not in args.nx_log) or (args.ny_log and ny not in args.ny_log):
                    continue
                rows.append(dict(mode='psu', nx_log2=nx, ny_log2=ny, network=network,
                                 case=f'ours_nx{nx}_ny{ny}_{network}'))
        for mode in ('zero', 'perm'):
            if args.mode not in ('all', mode):
                continue
            for ny in (11, 12, 13, 14):
                if args.ny_log and ny not in args.ny_log:
                    continue
                rows.append(dict(mode=mode, nx_log2=20, ny_log2=ny, network=network,
                                 case=f'{mode}_ny{ny}_{network}'))
    return rows


def command(job, args, directory):
    argv = [sys.executable, str(HERE/'run_case.py'), '--binary', str(args.binary),
            '--mode', job['mode'], '--nx-log', str(job['nx_log2']),
            '--ny-log', str(job['ny_log2']), '--network', job['network'],
            '--seed', args.seed, '--output', str(directory), '--offline-all8',
            '--timeout', str(args.timeout)]
    if job['mode'] == 'psu':
        argv += ['--compression', 'zstd', '--seeded-query', '--lazy-relinearize',
                 '--fused-ntt', '--avx512', '--small-field-polys', '--native-field-fft']
    return argv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'build/psu')
    parser.add_argument('--output', type=Path, default=ROOT/'results/paper')
    parser.add_argument('--mode', choices=['all','psu','zero','perm'], default='all')
    parser.add_argument('--network', nargs='+', choices=tuple(PROFILES), default=list(PROFILES))
    parser.add_argument('--nx-log', nargs='+', type=int, choices=[20,22,24])
    parser.add_argument('--ny-log', nargs='+', type=int, choices=[11,12,13,14])
    parser.add_argument('--seed', default='local-experiment-20261028')
    parser.add_argument('--timeout', type=int, default=7200)
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    planned = jobs(args)
    if not planned:
        raise RuntimeError('no paper case matches these filters')
    plan = dict(seed=args.seed, revision=REVISION, timeout_seconds=args.timeout, jobs=planned)
    if (root/'plan.json').exists() and json.loads((root/'plan.json').read_text()) != plan:
        raise RuntimeError('existing plan differs; use another output directory')
    write(root/'plan.json', plan)
    if args.plan_only:
        print(json.dumps({'planned_cases':len(planned), 'plan':str(root/'plan.json')}))
        return
    if not args.binary.is_file():
        raise FileNotFoundError(args.binary)
    if not set(range(16)).issubset(os.sched_getaffinity(0)):
        raise RuntimeError('the paper resource layout needs available CPU IDs 0 through 15')
    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    lock = (HERE/'.experiment.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state = dict(status='running', worker_pid=os.getpid(), total=len(planned), passed=0,
                 binary_sha256=binary_hash)
    active = None

    def stop(signum, frame):
        if active:
            subprocess.run(['systemctl','--user','stop',active], check=False)
        state['status'] = 'interrupted'
        write(root/'status.json', state)
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        for index, job in enumerate(planned):
            directory = root/'raw'/job['case']
            result_path = directory/'result.json'
            if result_path.exists():
                result = json.loads(result_path.read_text())
                manifest = json.loads((directory/'manifest.json').read_text())
                if (result.get('status') != 'PASS' or not result.get('correctness_verified')
                        or result.get('implementation_revision') != REVISION
                        or not result.get('phase_resources_verified')
                        or manifest['binary_sha256'] != binary_hash
                        or manifest['input_seed'] != args.seed):
                    raise RuntimeError(f'incompatible saved result: {directory}')
                state['passed'] += 1
                continue
            if directory.exists() and any(directory.iterdir()):
                raise RuntimeError(f'preserved incomplete attempt requires diagnosis: {directory}')
            directory.mkdir(parents=True, exist_ok=True)
            identity = hashlib.sha256(str(root).encode()).hexdigest()[:10]
            active = f'upsu-{identity}-{index}.scope'
            execution = ['systemd-run','--user','--scope','--quiet','--collect','--unit',active,
                         '-p','MemorySwapMax=0','-p','MemoryMax=50G','unshare','-Urn',
                         *command(job, args, directory)]
            write(directory/'command.json', {'argv':execution})
            state.update(case=job['case'], unit=active, updated_at=datetime.now().astimezone().isoformat())
            write(root/'status.json', state)
            print(json.dumps({'event':'start','case':job['case'],'passed':state['passed']}), flush=True)
            with (directory/'launcher.log').open('w') as log:
                process = subprocess.run(execution, stdout=log, stderr=subprocess.STDOUT,
                    env=dict(os.environ, UPSU_HOST_NETNS=os.readlink('/proc/self/ns/net')))
            active = None
            if process.returncode or not result_path.exists():
                raise RuntimeError(f'case failed; inspect preserved logs: {directory}')
            result = json.loads(result_path.read_text())
            if result.get('status') != 'PASS' or not result.get('correctness_verified'):
                raise RuntimeError(f'unverified case output: {directory}')
            state['passed'] += 1
            print(json.dumps({'event':'pass','case':job['case'],'passed':state['passed']}), flush=True)
        state.update(status='complete', updated_at=datetime.now().astimezone().isoformat())
        write(root/'status.json', state)
        export_results(root, planned)
    except Exception as error:
        state.update(status='needs_attention', reason=str(error))
        write(root/'status.json', state)
        raise
    finally:
        lock.close()


if __name__ == '__main__':
    main()
