"""Verify ordinary control under an owned live Mihomo TUN on disposable macOS/Windows runners."""

import argparse
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import queue
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


def request(config, method='GET', patch=None):
    data = None if patch is None else json.dumps(patch).encode()
    message = urllib.request.Request('http://' + config['external-controller'] + '/configs', data=data,
                                     headers={'Authorization': 'Bearer ' + config['secret'],
                                              'Content-Type': 'application/json'}, method=method)
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(message, timeout=3) as response:
        payload = response.read(1 << 20)
        return json.loads(payload) if payload else None


def disable_tun(config):
    request(config, 'PATCH', {'tun': {'enable': False}})
    assert request(config)['tun']['enable'] is False, 'owned TUN did not acknowledge shutdown'


def finish_runtime(process, config):
    try:
        if process.poll() is None:
            disable_tun(config)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def runtime(binary, path):
    assert os.environ.get('GITHUB_ACTIONS') == 'true', 'runtime is CI setup only'
    assert (sys.platform == 'darwin' and os.geteuid() == 0) or (
        sys.platform == 'win32' and ctypes.windll.shell32.IsUserAnAdmin()), 'owned TUN setup requires runner privilege'
    config = json.loads(path.read_text(encoding='utf-8'))
    process = subprocess.Popen([str(binary), '-d', str(path.parent), '-f', str(path)])
    closed = threading.Event()
    threading.Thread(target=lambda: (sys.stdin.buffer.read(), closed.set()), daemon=True).start()
    try:
        assert closed.wait(90), 'owned runtime watchdog expired'
    finally:
        finish_runtime(process, config)


def read_facts(process, timeout):
    result = queue.Queue(maxsize=1)

    def read():
        try:
            line = process.stdout.readline(16384)
            assert line.endswith('\n'), 'ordinary probe exited or returned oversized facts'
            result.put(json.loads(line))
        except BaseException as error:
            result.put(error)

    threading.Thread(target=read, daemon=True).start()
    value = result.get(timeout=timeout)
    if isinstance(value, BaseException):
        raise value
    return value


def verify(args):
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and sys.platform in ('darwin', 'win32'), 'requires a disposable native runner'
    binary, probe = args.mihomo.resolve(strict=True), args.probe.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='jcm-live-') as directory:
        root = Path(directory)
        config_path = root / 'config.json'
        ordinary = subprocess.Popen([str(probe), args.url], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        worker = None
        log_path = root / 'mihomo.log'
        try:
            facts = read_facts(ordinary, 20)
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserve:
                reserve.bind(('127.0.0.1', 0))
                controller = '127.0.0.1:' + str(reserve.getsockname()[1])
            config = {
                'external-controller': controller, 'secret': secrets.token_hex(32),
                'port': 0, 'socks-port': 0, 'mixed-port': 0, 'allow-lan': False, 'log-level': 'info',
                'tun': {'enable': True, 'stack': 'gvisor', 'auto-route': True,
                        'auto-detect-interface': True, 'inet4-address': ['198.18.0.1/30'], 'dns-hijack': []},
                'dns': {'enable': True, 'listen': facts['FakeDNS'], 'ipv6': False,
                        'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.19.0.1/16', 'fake-ip-filter': [],
                        'use-hosts': False, 'use-system-hosts': False,
                        'nameserver': [facts['Upstream']], 'default-nameserver': ['127.0.0.1']},
                'rules': ['MATCH,REJECT'],
            }
            if sys.platform == 'win32':
                config['tun']['device'] = 'jcm-live-' + root.name
                config['external-controller-pipe'] = r'\\.\pipe\verge-mihomo-test-' + root.name
            else:
                config['external-controller-unix'] = str(root / 'control.sock')
            config_path.write_text(json.dumps(config), encoding='utf-8')
            config_path.chmod(0o600)
            command = [sys.executable, '-u', str(Path(__file__).resolve()), '--runtime',
                       '--mihomo', str(binary), '--configuration', str(config_path)]
            if sys.platform == 'darwin':
                command = ['/usr/bin/sudo', '-n', '--', '/usr/bin/env', 'GITHUB_ACTIONS=true', *command]
            with log_path.open('w+', encoding='utf-8') as log:
                worker = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 15
                while True:
                    assert worker.poll() is None, 'owned runtime exited during startup'
                    try:
                        state = request(config)
                    except OSError:
                        state = None
                    if state and state['tun']['enable'] and state['tun'].get('device'):
                        break
                    assert time.monotonic() < deadline, 'owned runtime did not publish its TUN'
                    time.sleep(0.05)
                ordinary.stdin.write(json.dumps({'Phase': 'test', 'FakeRange': str(ipaddress.ip_network(config['dns']['fake-ip-range'], strict=False))}) + '\n')
                ordinary.stdin.flush()
                controlled = read_facts(ordinary, 55)
                assert controlled['phase'] == 'controlled' and controlled['stages'] == 4 and controlled['modes'] == 2
                print(json.dumps(controlled), flush=True)
                disable_tun(config)
                ordinary.stdin.write(json.dumps({'Phase': 'restored'}) + '\n')
                ordinary.stdin.flush()
                restored = read_facts(ordinary, 10)
                assert restored['phase'] == 'restored' and restored['interface'] == facts['Interface']
                assert ordinary.wait(timeout=5) == 0, 'ordinary control probe failed'
                print(json.dumps(restored), flush=True)
        finally:
            ordinary.stdin.close()
            if ordinary.poll() is None:
                try:
                    ordinary.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    ordinary.kill()
                    ordinary.wait(timeout=3)
            worker_status = 0
            if worker is not None:
                worker.stdin.close()
                worker_status = worker.wait(timeout=15)
            if log_path.exists():
                print(log_path.read_text(encoding='utf-8'), end='', flush=True)
            assert worker_status == 0, 'owned runtime cleanup failed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', action='store_true')
    parser.add_argument('--mihomo', type=Path, required=True)
    parser.add_argument('--configuration', type=Path)
    parser.add_argument('--probe', type=Path)
    parser.add_argument('--url')
    args = parser.parse_args()
    if args.runtime:
        runtime(args.mihomo, args.configuration)
    else:
        assert args.probe and args.url, 'requires the ordinary probe and explicit public test URL'
        verify(args)


if __name__ == '__main__':
    main()
