"""Check the production Go underlay against a competing TUN route in private namespaces."""
import argparse
import json
import os
from pathlib import Path
import pwd
import select
import socket
import subprocess
import sys
import threading
import time
from unix_device_probe import allocate_unix


def peer():
    print('namespace', flush=True)
    command = sys.stdin.readline()
    if not command:
        return
    assert command == 'start\n'
    tcp = socket.socket()
    tcp.bind(('198.18.0.6', 54321))
    tcp.listen()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('198.18.0.6', 54321))

    def streams():
        while True:
            conn, _ = tcp.accept()
            with conn:
                conn.settimeout(3)
                data = b''
                while len(data) < len(b'bound-original'):
                    part = conn.recv(64)
                    if not part:
                        break
                    data += part
                if data == b'bound-original':
                    conn.sendall(b'original-network')

    def datagrams():
        while True:
            data, address = udp.recvfrom(1024)
            if data == b'bound-original':
                udp.sendto(b'original-network', address)

    threading.Thread(target=streams, daemon=True).start()
    threading.Thread(target=datagrams, daemon=True).start()
    print('listening', flush=True)
    sys.stdin.read()


def ready(process, expected):
    assert select.select([process.stdout], [], [], 5)[0], 'private peer did not start'
    assert process.stdout.readline() == expected


def probe(binary, uid, allocator, route_backend):
    user = pwd.getpwuid(uid)
    server = subprocess.Popen(['unshare', '--net', '--', sys.executable, str(Path(__file__).resolve()), '--peer'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    tun = None
    cleanup_allocator = lambda: None
    source_routes = None
    source_snapshot = None
    try:
        ready(server, 'namespace\n')
        # These settings belong exclusively to the guarded private namespace.
        for name in ('all', 'default'):
            Path('/proc/sys/net/ipv4/conf/' + name + '/rp_filter').write_text('1')
        def ip(*args):
            subprocess.run(['ip', *args], check=True, timeout=5)
        def remote(*args):
            subprocess.run(['nsenter', '-t', str(server.pid), '-n', '--', 'ip', *args], check=True, timeout=5)
        ip('link', 'add', 'original0', 'type', 'veth', 'peer', 'name', 'peer0')
        ip('link', 'set', 'peer0', 'netns', str(server.pid))
        ip('addr', 'add', '192.0.2.1/24', 'dev', 'original0')
        ip('link', 'set', 'original0', 'up')
        remote('link', 'set', 'lo', 'up')
        remote('addr', 'add', '192.0.2.2/24', 'dev', 'peer0')
        remote('link', 'set', 'peer0', 'up')
        remote('addr', 'add', '198.18.0.6/32', 'dev', 'lo')
        ip('route', 'add', '198.18.0.0/24', 'via', '192.0.2.2', 'dev', 'original0')
        ip('route', 'add', 'default', 'via', '192.0.2.2', 'dev', 'original0')
        tun, capture, cleanup_allocator = allocate_unix(allocator)
        original_routes = json.loads(subprocess.check_output(['ip', '-N', '-j', '-4', 'route', 'show', 'table', 'all'], text=True))
        original_rules = json.loads(subprocess.check_output(['ip', '-N', '-j', '-4', 'rule', 'show'], text=True))
        # The formal backend owns the source lookup; EOF restores it in another process.
        source_routes = subprocess.Popen([str(route_backend), '--hold', 'original0', '192.0.2.1', '192.0.2.2', '198.18.0.6/32'],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert select.select([source_routes.stdout], [], [], 10)[0], 'native source backend did not confirm application'
        source_snapshot = json.loads(source_routes.stdout.readline())
        assert source_snapshot['source'] == '192.0.2.1' and source_snapshot['interface'] == 'original0'
        for name in ('all', 'original0'):
            assert Path('/proc/sys/net/ipv4/conf/' + name + '/rp_filter').read_text().strip() == '1'
        route = json.loads(subprocess.check_output(['ip', '-j', 'route', 'get', '198.18.0.6'], text=True))
        assert route[0]['dev'] == capture, 'competing capture route not selected'
        original_route = json.loads(subprocess.check_output(
            ['ip', '-j', 'route', 'get', '198.18.0.6', 'from', '192.0.2.1'], text=True))
        assert original_route[0]['dev'] == 'original0' and str(original_route[0]['table']) == str(source_snapshot['table']), original_route
        server.stdin.write('start\n')
        server.stdin.flush()
        ready(server, 'listening\n')
        def ordinary(mode, interface):
            return subprocess.run([str(binary), mode, interface], user=uid, group=user.pw_gid, extra_groups=[],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        captured = ordinary('capture', '')
        assert captured.returncode == 0, captured.stderr
        deadline = time.monotonic() + 3
        while True:
            assert select.select([tun], [], [], max(0, deadline - time.monotonic()))[0], 'unbound flow did not enter capture TUN'
            packet = os.read(tun, 65536)
            if len(packet) >= 28 and packet[0] >> 4 == 4 and packet[9] == socket.IPPROTO_UDP:
                offset = (packet[0] & 15) * 4
                if packet[offset + 8:] == b'capture-probe':
                    assert packet[12:16] == socket.inet_aton('198.18.0.1'), 'unbound flow acquired original source'
                    break
        original = ordinary('original', 'original0')
        assert original.returncode == 0, original.stderr
        print(original.stdout, end='', flush=True)
        automatic = ordinary('automatic', '')
        assert automatic.returncode == 0, automatic.stderr
        print(automatic.stdout, end='', flush=True)
        missing = ordinary('original', 'missing0')
        assert missing.returncode != 0, 'missing original interface silently fell back'
    finally:
        try:
            if source_routes is not None:
                source_routes.stdin.close()
                source_routes.stdin = None
                try:
                    output, error = source_routes.communicate(timeout=12)
                except subprocess.TimeoutExpired:
                    source_routes.kill()
                    source_routes.wait(timeout=3)
                    raise AssertionError('native source backend did not finish independent recovery')
                assert source_routes.returncode == 0, error
                print(output, end='', flush=True)
                if source_snapshot is not None:
                    after_routes = json.loads(subprocess.check_output(['ip', '-N', '-j', '-4', 'route', 'show', 'table', 'all'], text=True))
                    after_rules = json.loads(subprocess.check_output(['ip', '-N', '-j', '-4', 'rule', 'show'], text=True))
                    normalize = lambda rows: sorted(json.dumps(row, sort_keys=True) for row in rows)
                    assert normalize(after_routes) == normalize(original_routes) and after_rules == original_rules, 'owned source recovery changed the original route/rule inventory'
        finally:
            if tun is not None:
                os.close(tun)
            cleanup_allocator()
            if server.stdin:
                server.stdin.close()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', action='store_true')
    parser.add_argument('--probe', type=Path)
    parser.add_argument('--uid', type=int)
    parser.add_argument('--allocator', type=Path)
    parser.add_argument('--routes', type=Path)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino:
        parser.error('requires root inside a private Linux network namespace')
    if args.peer:
        peer()
    else:
        if (not args.probe or not args.probe.is_file() or not args.uid or args.uid <= 0 or not args.allocator
                or not args.allocator.is_file() or not args.routes or not args.routes.is_file()):
            parser.error('requires compiled Go, native allocator/source-route backends and an ordinary uid')
        probe(args.probe.resolve(), args.uid, args.allocator.resolve(), args.routes.resolve())
