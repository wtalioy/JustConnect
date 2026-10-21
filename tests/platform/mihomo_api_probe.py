"""Probe API readback on an owned Mihomo instance, never an existing controller."""

import argparse
from contextlib import contextmanager
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


@contextmanager
def dns_stub(ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1', 0))
        server.settimeout(0.1)
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    data, peer = server.recvfrom(4096)
                except TimeoutError:
                    continue
                if len(data) < 17 or data[4:6] != b'\0\1':
                    continue
                end = data.find(b'\0', 12) + 5
                if end < 17 or end > len(data) or data[end-4:end] != b'\0\1\0\1':
                    continue
                reply = (data[:2] + b'\x81\x80\0\1\0\1\0\0\0\0' + data[12:end]
                         + b'\xc0\x0c\0\1\0\1\0\0\0\0\0\4' + socket.inet_aton(ip))
                server.sendto(reply, peer)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            yield f'127.0.0.1:{server.getsockname()[1]}'
        finally:
            stop.set()
            worker.join(timeout=2)
            assert not worker.is_alive(), 'owned DNS stub survived cleanup'


def probe(binary, first_dns, second_dns):
    binary = binary.resolve(strict=True)
    version = subprocess.check_output([str(binary), '-v'], text=True, timeout=10).strip()
    nonce = secrets.token_hex(16)
    marker = f'jc-{nonce}.invalid'
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        dns_port = reservation.getsockname()[1]
    config = {
        'external-controller': f'127.0.0.1:{port}', 'secret': secrets.token_urlsafe(32),
        'allow-lan': False, 'bind-address': '127.0.0.1', 'mode': 'rule',
        'port': 0, 'socks-port': 0, 'mixed-port': 0, 'redir-port': 0, 'tproxy-port': 0,
        'log-level': 'silent', 'tun': {'enable': False}, 'ipv6': False,
        'profile': {'store-selected': False, 'store-fake-ip': False},
        'dns': {'enable': True, 'listen': f'127.0.0.1:{dns_port}', 'use-hosts': True,
                'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                'fake-ip-filter': [], 'fake-ip-filter-mode': 'blacklist',
                'nameserver': [first_dns], 'default-nameserver': ['127.0.0.1'],
                'fallback': []},
        'rules': [f'DOMAIN,{marker},DIRECT', 'MATCH,REJECT'],
    }
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(method, path, payload=None, authenticated=True):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {'Content-Type': 'application/json'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + config['secret']
        req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=data,
                                     headers=headers, method=method)
        with opener.open(req, timeout=3) as response:
            body = response.read(4 * 1024 * 1024 + 1)
            assert len(body) <= 4 * 1024 * 1024, 'unbounded API response'
            return json.loads(body) if body else None

    def answer():
        name = secrets.token_hex(4) + '.' + marker
        reply = request('GET', f'/dns/query?name={name}&type=A')
        return [entry['data'] for entry in reply.get('Answer', []) if entry['type'] == 1]

    def listener_answer():
        name = secrets.token_hex(4) + '.' + marker
        labels = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'
        identity = secrets.randbelow(65536)
        query = struct.pack('!6H', identity, 0x100, 1, 0, 0, 0) + labels + b'\0\1\0\1'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.connect(('127.0.0.1', dns_port))
            client.send(query)
            reply = client.recv(4096)
        header = struct.unpack('!6H', reply[:12])
        assert header[0] == identity and header[1] & 15 == 0 and header[2:] == (1, 1, 0, 0)
        assert reply[-14:-10] == b'\0\1\0\1' and reply[-6:-4] == b'\0\4', 'unexpected owned DNS answer'
        return ipaddress.ip_address(reply[-4:])

    with tempfile.TemporaryDirectory(prefix='justconnect-mihomo-api-') as directory:
        root = Path(directory)
        path = root / 'config.json'
        path.write_text(json.dumps(config), encoding='utf-8')
        with (root / 'process.log').open('w', encoding='utf-8') as log:
            process = subprocess.Popen([str(binary), '-d', str(root), '-f', str(path)],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while True:
                    assert process.poll() is None, 'owned instance exited before readiness'
                    try:
                        api_version = request('GET', '/version')
                        rules = request('GET', '/rules')['rules']
                        break
                    except (urllib.error.URLError, TimeoutError):
                        assert time.monotonic() < deadline, 'owned API did not become ready'
                        time.sleep(0.1)
                # A port race must never authorize writes to somebody else's controller.
                assert any(rule['payload'] == marker for rule in rules), 'controller ownership mismatch'
                try:
                    request('GET', '/configs', authenticated=False)
                except urllib.error.HTTPError as error:
                    assert error.code == 401, 'unexpected unauthenticated response'
                else:
                    raise AssertionError('controller did not enforce authentication')
                initial = request('GET', '/configs')
                assert initial['mode'] == 'rule' and not initial['tun']['enable']
                assert answer() == ['192.0.2.10'], 'owned DNS baseline failed'
                assert listener_answer() in ipaddress.ip_network('198.18.0.0/16'), 'owned DNS listener did not use Fake-IP'
                request('PATCH', '/configs', {'mode': 'direct'})
                assert request('GET', '/configs')['mode'] == 'direct', 'mode PATCH was not applied'
                exclusion = ['192.0.2.0/30']
                request('PATCH', '/configs', {'tun': dict(initial['tun'], **{'route-exclude-address': exclusion})})
                patched_tun = request('GET', '/configs')['tun']
                assert not patched_tun['enable'], 'disabled TUN was enabled by API update'
                request('PATCH', '/configs', {'rules': [f'DOMAIN,{marker},REJECT', 'MATCH,DIRECT'],
                                             'dns': dict(config['dns'], nameserver=[second_dns])})
                patched_rules = request('GET', '/rules')['rules']
                patched_answer = answer()
                updated = dict(config, mode='global', dns=dict(config['dns'], nameserver=[second_dns]),
                               rules=[f'DOMAIN,{marker},REJECT', 'MATCH,DIRECT'])
                request('PUT', '/configs?force=true', {'payload': json.dumps(updated)})
                reloaded = request('GET', '/configs')
                reloaded_rules = request('GET', '/rules')['rules']
                assert reloaded['mode'] == 'global' and not reloaded['tun']['enable']
                assert reloaded_rules[0]['payload'] == marker and reloaded_rules[0]['proxy'] == 'REJECT'
                assert answer() == ['192.0.2.30'], 'PUT reload did not apply DNS'
                try:
                    request('PUT', '/configs?force=true', {'payload': 'rules: [not-a-valid-rule]'})
                except urllib.error.HTTPError as error:
                    assert error.code == 400, 'unexpected invalid-update classification'
                else:
                    raise AssertionError('invalid full configuration accepted')
                assert request('GET', '/configs')['mode'] == 'global'
                assert request('GET', '/rules')['rules'] == reloaded_rules
                request('PUT', '/configs?force=true', {'payload': json.dumps(config)})
                assert request('GET', '/configs')['mode'] == initial['mode']
                assert request('GET', '/rules')['rules'] == rules and answer() == ['192.0.2.10']
                report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                          'version': version, 'api_version': api_version,
                          'mode_patch_readback': True, 'rules_patch_applied': patched_rules != rules,
                          'dns_query_api_returns_real_ip_in_fake_ip_mode': True,
                          'dns_patch_applied': patched_answer != ['192.0.2.10'],
                          'disabled_tun_exclusion_patch_readback': patched_tun.get('route-exclude-address') == exclusion,
                          'put_rules_dns_readback': True, 'invalid_update_keeps_previous': True,
                          'restore_readback': True, 'config_readback_keys': sorted(initial)}
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
        # Only the process created above is stopped; no GUI, service or system settings are touched.
        with socket.socket() as check:
            assert check.connect_ex(('127.0.0.1', port)) != 0, 'owned controller survived cleanup'
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
    with dns_stub('192.0.2.10') as first, dns_stub('192.0.2.30') as second:
        print(json.dumps(probe(args.binary, first, second), indent=2))
