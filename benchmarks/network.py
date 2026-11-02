"""Two independent directional rate limits inside a fresh network namespace."""
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

PROFILES = {
    '10Gbps': (10000, 0.05),
    '100Mbps': (100, 80),
    '10Mbps': (10, 80),
    '1Mbps': (1, 80),
}


def command(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def configure(profile, port, listeners=None):
    host_namespace = os.environ.get('UPSU_HOST_NETNS')
    if not host_namespace or os.readlink('/proc/self/ns/net') == host_namespace:
        raise RuntimeError('refusing to alter host network; run with unshare -Urn')
    listeners = listeners or {port: 0, port + 1: 1}
    # Some native listeners start after lengthy preprocessing. Keep their fixed
    # ports out of the client's ephemeral allocation range in this namespace.
    reserved = ','.join(map(str, sorted(set(listeners) | {port})))
    Path('/proc/sys/net/ipv4/ip_local_reserved_ports').write_text(reserved + '\n')
    rate, rtt = PROFILES[profile]
    command('ip', 'link', 'set', 'lo', 'up')
    command('ip', 'link', 'set', 'lo', 'mtu', '1500')
    command('tc', 'qdisc', 'replace', 'dev', 'lo', 'root', 'handle', '1:', 'htb', 'default', '30')
    command('tc', 'class', 'add', 'dev', 'lo', 'parent', '1:', 'classid', '1:30',
            'htb', 'rate', '10000mbit')
    for direction in (10, 20):
        command('tc', 'class', 'add', 'dev', 'lo', 'parent', '1:', 'classid', f'1:{direction}',
                'htb', 'rate', f'{rate}mbit', 'ceil', f'{rate}mbit',
                'burst', str(max(1600, min(1048576, rate * 1250))), 'quantum', '1514')
        command('tc', 'qdisc', 'add', 'dev', 'lo', 'parent', f'1:{direction}',
                'handle', f'{direction}:', 'netem', 'delay', f'{rtt / 2:g}ms', 'limit', '100000')
    # Shape data and returning ACKs for every protocol listener.
    filters = []
    for service_port, role in listeners.items():
        filters.extend([('dport', service_port, 10 if role == 0 else 20),
                        ('sport', service_port, 20 if role == 0 else 10)])
    for priority, (field, value, direction) in enumerate(filters, 1):
        command('tc', 'filter', 'add', 'dev', 'lo', 'protocol', 'ip', 'parent', '1:',
                'prio', str(priority), 'u32', 'match', 'ip', 'protocol', '6', '0xff',
                'match', 'ip', field, str(value), '0xffff', 'flowid', f'1:{direction}')
    return {'bandwidth_mbps_per_direction': rate, 'configured_rtt_ms': rtt,
            'listener_roles': listeners,
            'reserved_service_ports': reserved,
            'network_namespace': os.readlink('/proc/self/ns/net'),
            'method': 'Linux tc HTB per direction plus netem one-way delay on isolated loopback',
            'mtu_bytes': 1500, 'tcp_echo_rtt_ms': echo_rtt(port), 'before': statistics()}


def echo_rtt(port):
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', port))
        listener.listen(1)

        def echo():
            connection, _ = listener.accept()
            with connection:
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                for _ in range(4):
                    data = connection.recv(1)
                    connection.sendall(data)

        worker = threading.Thread(target=echo)
        worker.start()
        samples = []
        with socket.create_connection(('127.0.0.1', port), timeout=5) as client:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for _ in range(4):
                start = time.monotonic()
                client.sendall(b'x')
                if client.recv(1) != b'x':
                    raise RuntimeError('TCP echo failed')
                samples.append((time.monotonic() - start) * 1000)
        worker.join()
        return samples[1:]


def statistics():
    return {'qdisc': json.loads(command('tc', '-j', '-s', 'qdisc', 'show', 'dev', 'lo')),
            'classes_text': command('tc', '-s', 'class', 'show', 'dev', 'lo')}
