#!/usr/bin/env python3
"""Run a FastUPSU paper case in an isolated, shaped network namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent
from network import configure, statistics, PROFILES
from parameters import public_parameters


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def metric(text, label):
    matches = re.findall(r'^\s*' + re.escape(label) + r'\s*:\s*([\d.eE+-]+)', text, re.M)
    if not matches:
        raise RuntimeError('missing metric: ' + label)
    return float(matches[-1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['psu', 's3mt', 'zero', 'perm'], default='psu')
    parser.add_argument('--nx-log', type=int, default=20)
    parser.add_argument('--ny-log', type=int, default=12)
    parser.add_argument('--network', choices=tuple(PROFILES), default='10Gbps')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=SOURCE/'build/psu')
    parser.add_argument('--timeout', type=int, default=7200)
    parser.add_argument('--seed', default=None)
    parser.add_argument('--compression',choices=['none','zstd'],default='none')
    parser.add_argument('--seeded-query', action='store_true')
    parser.add_argument('--lazy-relinearize', action='store_true')
    parser.add_argument('--fused-ntt', action='store_true')
    parser.add_argument('--avx512', action='store_true')
    parser.add_argument('--small-field-polys', action='store_true')
    parser.add_argument('--native-field-fft', action='store_true')
    parser.add_argument('--offline-all8', action='store_true')
    parser.add_argument('--perm-batch-log2', type=int, choices=range(10,27), default=18)
    parser.add_argument('--gmw-triple-batch-log2', type=int, choices=range(16,26), default=20)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if (out/'manifest.json').exists():
        raise RuntimeError('case directory already contains an experiment')
    params = public_parameters(args.nx_log, args.ny_log)
    executable = args.binary.resolve()
    if not executable.is_file():
        raise FileNotFoundError(executable)
    settings = json.loads((SOURCE/'settings.json').read_text())
    settings = {k:v for k,v in settings.items() if not k.startswith('profile_') and k not in ['default_profile', 'profiles']}
    settings.update(medium_nx=params['nx'], medium_ny=params['ny'], medium_cap=128,
                    simple_hash_bins=params['bins'], alpha=params['alpha'],
                    coeff_modulus_bits={20:[46]*4, 22:[48]*4, 24:[56,56,56,50]}[args.nx_log],
                    offline_threads=8, online_threads=1, synthetic_online=False,
                    salted_hash=args.mode=='psu')
    settings.pop('dh_oprf', None)
    write(out/'settings.json', settings)
    environment = dict(os.environ, PSU_SETTINGS_FILE=str(out/'settings.json'), PSU_PROFILE='',
        PSU_PUBLIC_SUB_BIN_SIZE=str(params['degree']), PSU_SIGMA1_BITS=str(params['sigma1_bits']),
        PSU_OTE_VALUE_BITS='128', PSU_RANDOM_INPUT_SEED=args.seed or os.urandom(32).hex(),
        PSU_USE_AVX512='1' if args.avx512 else '0',
        PSU_SMALL_FIELD_POLYS='1' if args.small_field_polys else '0',
        PSU_NATIVE_FIELD_FFT='1' if args.native_field_fft else '0',
        PSU_PHASE_THREADS_V1='1' if args.offline_all8 else '0',
        PSU_PERM_BATCH_ROWS=str(1 << args.perm_batch_log2),
        PSU_PEQT_GMW_TRIPLE_BATCH=str(1 << args.gmw_triple_batch_log2),
        PSU_FUSED_NTT='1' if args.fused_ntt else '0',
        PSU_LAZY_RELINEARIZE='1' if args.lazy_relinearize else '0',
        PSU_TRACE_TIMES='1', PSU_SEEDED_QUERY='1' if args.seeded_query else '0',
        PSU_SERIALIZATION_COMPRESSION='1' if args.compression=='zstd' else '0',
        PSU_PARTIES='127.0.0.1:23000,127.0.0.1:23001', PSU_OTE_ADDRESS='127.0.0.1:25050',
        PSU_PERM_ADDRESS='127.0.0.1:25150', PSU_PEQT_ADDRESS='127.0.0.1:25200',
        PSU_LOCAL_TCP_PORT='24000', PSU_GMW_THREADS='1', PSU_PERM_THREADS='1',
        OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', PSU_LINK_RECV_TIMEOUT_MS=str(args.timeout*1000))
    listeners = {23000:0, 23001:1, 24000:0, 25050:1, 25150:0}
    listeners.update({25200+i:1 for i in range(32)})
    network = configure(args.network, 23000, listeners)
    write(out/'network.json', network)
    manifest = dict(protocol='FastUPSU', mode=args.mode, network=args.network, nx_log2=args.nx_log,
        ny_log2=args.ny_log, parameters=params, intersection_size=128, input_bits=128,
        input_seed=environment['PSU_RANDOM_INPUT_SEED'],
        binary_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        repetitions=1, warmup=False, source_commit=subprocess.check_output(
            ['git','-C',str(SOURCE),'rev-parse','HEAD'],text=True).strip(),
        offline_cpus=[0,1,2,3,4,5,6,7], online_cpus=[0,8],
        source_modified=True, time_unit='s', communication_unit='bytes')
    manifest['implementation_revision']='paper-20261102-salted-blake3-v1'
    manifest['max_source_power_depth']=settings['query_depth']
    manifest['eqote_payload_bits']=128
    manifest['eqote_validity_bytes_per_branch']=1
    manifest['avx512_requested']=args.avx512
    manifest['small_field_polys']=args.small_field_polys
    manifest['native_field_fft']=args.native_field_fft
    manifest['native_field_fft_min_points']=512
    manifest['input_encoding']='salted-blake3' if args.mode=='psu' else 'not_used'
    manifest['input_encoding_bits']=128 if args.mode=='psu' else None
    manifest['salt_bits']=128 if args.mode=='psu' else None
    manifest['salt_timing']='fresh offline; revealed only online; single-use' if args.mode=='psu' else None
    manifest['bin_hash']='BLAKE3' if args.mode in ('psu','s3mt') else 'not_used'
    manifest['input_fixture_hash']='SHA256 unchanged; raw inputs and order fixed by seed before process launch'
    manifest['blake3_version']='1.8.2'
    manifest['offline_cpus_by_role']={'receiver':list(range(8)), 'sender':list(range(8,16)) if args.offline_all8 else [8]}
    manifest['perm_correlation_batch_size']=1 << args.perm_batch_log2
    manifest['gmw_triple_batch_size']=1 << args.gmw_triple_batch_log2
    manifest['silent_correlation_encoding']='ExConv7x24'
    if args.offline_all8:
        manifest['resource_revision']='offline8-per-party-online1-v1'
        manifest['offline_threads_per_party']=8
        manifest['online_threads_per_party']=1
    manifest['fused_ntt']=args.fused_ntt
    manifest['lazy_relinearize']=args.lazy_relinearize
    manifest['seeded_query']=args.seeded_query
    manifest['compression']=args.compression
    manifest['diagnostic_only']=bool(os.environ.get('PSU_DIAGNOSTIC_DIR'))
    write(out/'manifest.json', manifest)
    processes, logs = [], []
    started = time.monotonic()
    try:
        if args.mode in ('psu', 's3mt'):
            roles = [('receiver',0),('sender',8)]
        else:
            roles = [('packed-zero-bench' if args.mode=='zero' else 'perm-bench',0)]
        for role, cpu in roles:
            mode = 's3mt-' + role if args.mode == 's3mt' else role
            env = dict(environment, PSU_MODE=mode, PSU_PRIMITIVE_N=str(1<<args.ny_log), PSU_THREADS='1')
            cpus = list(range(8)) if role == 'receiver' else (list(range(8,16)) if args.offline_all8 else [cpu])
            if args.mode in ('psu', 's3mt'):
                env.update(PSU_ONLINE_CPU=str(cpu), PSU_OFFLINE_CPUS=','.join(map(str,cpus)))
            else:
                cpus = [0,8]
                env.update(PSU_BENCH_CPU0='0',PSU_BENCH_CPU1='8')
                if args.offline_all8:
                    env.update(PSU_OFFLINE_CPUS=','.join(map(str,range(16))),PSU_ONLINE_CPU='0,8')
            log = (out/f'{role}.log').open('w')
            logs.append(log)
            process = subprocess.Popen([str(executable)], cwd=SOURCE, env=env,
                stdout=log, stderr=subprocess.STDOUT,
                preexec_fn=lambda cpus=cpus: os.sched_setaffinity(0, cpus))
            processes.append(process)
        while any(p.poll() is None for p in processes):
            if any(p.poll() not in (None,0) for p in processes):
                raise RuntimeError('protocol process failed')
            if time.monotonic()-started > args.timeout:
                raise TimeoutError('native protocol exceeded experiment timeout')
            time.sleep(0.25)
        if any(p.returncode != 0 for p in processes):
            raise RuntimeError('protocol process failed')
        for log in logs: log.flush()
        texts = [(out/f'{role}.log').read_text() for role,_ in roles]
        if not any('[CORRECT]' in t for t in texts) or any('[WRONG!]' in t for t in texts):
            raise RuntimeError('output correctness check failed')
        if args.mode == 'psu' and 'Complete union verified: yes' not in texts[0]:
            raise RuntimeError('complete union was not verified')
        if args.offline_all8 and args.mode in ('psu','s3mt'):
            for text, (role,cpu) in zip(texts,roles):
                cpus = ','.join(map(str,range(8) if role=='receiver' else range(8,16)))
                for marker in [f'[resource_phase] offline threads=8 cpus={cpus} stage=interactive_setup all_tasks_verified=yes',
                               f'[resource_phase] online threads=1 cpus={cpu} stage=before_online_encoding all_tasks_verified=yes']:
                    if marker not in text:
                        raise RuntimeError('missing verified phase resource boundary: '+marker)
        if args.offline_all8 and args.mode in ('zero','perm'):
            for rank,cpu in [(0,0),(1,8)]:
                for phase,count in [('offline',8),('online',1)]:
                    marker=f'[primitive_resource_phase] {phase} rank={rank} threads={count} first_cpu={cpu} affinity_verified=yes'
                    if marker not in texts[0]:
                        raise RuntimeError('missing primitive resource boundary: '+marker)
        if args.mode=='psu':
            for text,marker in zip(texts,[
                    '[input_encoding] receiver sent salt_bits=128 hash=BLAKE3 phase=online',
                    '[input_encoding] sender received salt_bits=128 hash=BLAKE3 phase=online']):
                if text.count(marker)!=1:
                    raise RuntimeError('missing or reused online salted-hash encoding: '+marker)
                if args.offline_all8 and text.index(marker) < text.index('stage=before_online_encoding all_tasks_verified=yes'):
                    raise RuntimeError('salt disclosed before verified online boundary')
        result = dict(status='PASS', offline_seconds=max(metric(t,'Setup time') for t in texts),
                      online_seconds=max(metric(t,'Online time') for t in texts),
                      offline_bytes=int(max(metric(t,'Setup bytes') for t in texts)),
                      online_bytes=int(max(metric(t,'Online bytes') for t in texts)),
                      total_bytes=int(max(metric(t,'Total bytes') for t in texts)),
                      wall_seconds=time.monotonic()-started, correctness_verified=True)
        result['total_seconds'] = result['offline_seconds']+result['online_seconds']
        result['implementation_revision']='paper-20261102-salted-blake3-v1'
        if args.mode=='psu':
            result['input_encoding']='salted-blake3'
            result['salt_online_boundary_verified']=args.offline_all8
        if args.offline_all8:
            result['resource_revision']='offline8-per-party-online1-v1'
            result['phase_resources_verified']=True
            if args.mode in ('zero','perm'):
                result['resource_scope']='two local party workers; online worker CPUs0/8; shared asynchronous I/O confined to CPUs0,8'
        if args.mode=='psu':
            result['s3mt_online_seconds']=max(metric(t,'S3MT online time') for t in texts)
            result['s3mt_online_bytes']=int(max(metric(t,'S3MT online bytes') for t in texts))
            saved=int(sum(metric(t,'FHE saved bytes') for t in texts))
            saved_keys=int(max(metric(t,'FHE key saved bytes') for t in texts))
            result['uncompressed_offline_bytes']=result['offline_bytes']+saved_keys
            result['uncompressed_online_bytes']=result['online_bytes']+saved-saved_keys
            result['serialization_saved_bytes']=saved
        network['after'] = statistics()
        for entry in Path('/proc/self/cgroup').read_text().splitlines():
            if entry.startswith('0::'):
                group = Path('/sys/fs/cgroup') / entry[3:].lstrip('/')
                if group.name.startswith('upsu-') and (group/'memory.peak').exists():
                    result['cgroup_peak_memory_bytes'] = int((group/'memory.peak').read_text())
                    result['memory_scope'] = 'both parties and experiment runner in this case scope'
        write(out/'network.json', network)
        write(out/'result.json', result)
        print(json.dumps(result), flush=True)
    except BaseException as error:
        write(out/'failure.json',dict(type=type(error).__name__,reason=str(error)))
        raise
    finally:
        for p in processes:
            if p.poll() is None: p.kill()
            p.wait()
        for log in logs: log.close()


if __name__=='__main__':
    main()
