"""Run a live rejecting Mihomo TUN and ordinary Go control in private Linux namespaces."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import select
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--mihomo', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and args.uid != 0
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'requires a new private network namespace'
    probe, binary = args.probe.resolve(strict=True), args.mihomo.resolve(strict=True)
    user = pwd.getpwuid(args.uid)
    original, tunnel, target = 'jc-original0', 'jc-mihomo', '198.51.100.6'

    def ip(*values, peer=None, capture=False):
        command = ['ip', *values]
        if peer is not None:
            command = ['nsenter', '-t', str(peer), '-n', '--', *command]
        return subprocess.run(command, check=True, timeout=5, text=True,
                              stdout=subprocess.PIPE if capture else subprocess.DEVNULL).stdout

    def read_line(process, seconds=5):
        assert select.select([process.stdout], [], [], seconds)[0], 'owned peer readiness timeout'
        line = process.stdout.readline()
        assert line, 'owned peer exited before readiness'
        return line

    peer = subprocess.Popen(['unshare', '--net', '--', str(probe), 'peer', target],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    mihomo = None
    with tempfile.TemporaryDirectory(prefix='jcm-tun-') as directory:
        root = Path(directory)
        # The ordinary client may reach the verified socket, but cannot read the root-owned configuration.
        root.chmod(0o711)
        log_path = root / 'mihomo.log'
        try:
            assert read_line(peer) == 'namespace\n'
            ip('link', 'set', 'lo', 'up')
            ip('link', 'add', original, 'type', 'veth', 'peer', 'name', 'peer0')
            ip('link', 'set', 'peer0', 'netns', str(peer.pid))
            ip('addr', 'add', '192.0.2.1/24', 'dev', original)
            ip('link', 'set', original, 'up')
            for name in ('all', 'default', original):
                Path('/proc/sys/net/ipv4/conf/' + name + '/rp_filter').write_text('1')
            ip('link', 'set', 'lo', 'up', peer=peer.pid)
            ip('addr', 'add', '192.0.2.2/24', 'dev', 'peer0', peer=peer.pid)
            ip('link', 'set', 'peer0', 'up', peer=peer.pid)
            ip('addr', 'add', target + '/32', 'dev', 'lo', peer=peer.pid)
            ip('route', 'add', 'default', 'via', '192.0.2.2', 'dev', original)
            peer.stdin.write('start\n')
            peer.stdin.flush()
            facts = json.loads(read_line(peer))
            facts.update(Interface=original, Source='192.0.2.1')
            facts_path = root / 'peer.json'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
                reserve.bind(('127.0.0.1', 0))
                dns_address = '127.0.0.1:' + str(reserve.getsockname()[1])
            ipc = str(root / 'control.sock')
            config = {
                'external-controller-unix': ipc, 'log-level': 'silent', 'allow-lan': False,
                'port': 0, 'socks-port': 0, 'mixed-port': 0,
                'tun': {'enable': True, 'device': tunnel, 'stack': 'gvisor', 'auto-route': True,
                        'auto-detect-interface': True, 'inet4-address': ['198.18.0.1/30'], 'dns-hijack': []},
                'dns': {'enable': True, 'listen': dns_address, 'ipv6': False,
                        'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.19.0.1/16',
                        'use-hosts': False, 'use-system-hosts': False,
                        'nameserver': [facts['DNS']], 'default-nameserver': ['127.0.0.1']},
                'rules': ['MATCH,REJECT'],
            }
            facts.update(FakeDNS=dns_address, FakeRange=str(ipaddress.ip_network(config['dns']['fake-ip-range'], strict=False)))
            facts_path.write_text(json.dumps(facts), encoding='utf-8')
            os.chown(facts_path, args.uid, user.pw_gid)
            facts_path.chmod(0o600)
            config_path = root / 'config.json'
            config_path.write_text(json.dumps(config), encoding='utf-8')
            config_path.chmod(0o600)
            with log_path.open('wb') as log:
                mihomo = subprocess.Popen([str(binary), '-d', directory, '-f', str(config_path), '-ext-ctl-unix', ipc],
                                          stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 10
                while True:
                    assert mihomo.poll() is None, 'owned Mihomo exited before TUN readiness'
                    route = json.loads(ip('-j', 'route', 'get', target, 'uid', str(args.uid), capture=True))
                    if Path(ipc).exists() and route and route[0]['dev'] == tunnel:
                        break
                    assert time.monotonic() < deadline, 'Mihomo did not install its real capture route'
                    time.sleep(0.05)

                def ordinary(mode):
                    return subprocess.run([str(probe), mode, str(facts_path)], user=args.uid, group=user.pw_gid,
                                          extra_groups=[], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          timeout=25)

                def packets():
                    row = json.loads(ip('-s', '-j', 'link', 'show', 'dev', tunnel, capture=True))[0]['stats64']
                    return row['rx']['packets'] + row['tx']['packets']

                assert all(Path('/proc/sys/net/ipv4/conf/' + name + '/rp_filter').read_text().strip() == '1'
                           for name in ('all', original)), 'strict reverse-path checks were relaxed'
                before = packets()
                captured = ordinary('captured')
                assert captured.returncode == 0, captured.stderr
                assert packets() > before, 'unbound TLS did not enter the actual Mihomo TUN'
                connected = ordinary('control')
                assert connected.returncode == 0, connected.stderr
                print(captured.stdout + connected.stdout, end='', flush=True)
                deadline = time.monotonic() + 5
                mihomo.terminate()
                mihomo.wait(timeout=max(0, deadline - time.monotonic()))
                while True:
                    restored = json.loads(ip('-j', 'route', 'get', target, 'uid', str(args.uid), capture=True))
                    if restored and restored[0]['dev'] == original:
                        break
                    assert time.monotonic() < deadline, ('owned Mihomo did not release its capture route', restored)
                    time.sleep(0.05)
                print('PASS: owned Mihomo TUN stopped and original route restored', flush=True)
        finally:
            if mihomo is not None and mihomo.poll() is None:
                mihomo.kill()
                mihomo.wait(timeout=5)
            peer.stdin.close()
            try:
                peer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                peer.kill()
                peer.wait(timeout=5)
            if log_path.exists():
                print(log_path.read_text(encoding='utf-8'), end='', flush=True)


if __name__ == '__main__':
    main()
