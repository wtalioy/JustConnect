"""Check the production Go underlay against a competing TUN route in private namespaces."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import select
import socket
import struct
import subprocess
import sys
import threading
import time


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


def probe(binary, uid):
    user = pwd.getpwuid(uid)
    server = subprocess.Popen(['unshare', '--net', '--', sys.executable, str(Path(__file__).resolve()), '--peer'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    tun = None
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
        tun = os.open('/dev/net/tun', os.O_RDWR | os.O_CLOEXEC)
        fcntl.ioctl(tun, 0x400454ca, struct.pack('16sH22x', b'capture0', 0x1001))
        ip('addr', 'add', '198.18.0.1/30', 'dev', 'capture0')
        ip('link', 'set', 'capture0', 'up')
        ip('route', 'add', '198.18.0.6/32', 'dev', 'capture0')
        # Preserve the selected original source and its reverse path without relaxing rp_filter.
        ip('route', 'add', '192.0.2.0/24', 'dev', 'original0', 'table', '42117')
        ip('route', 'add', '198.18.0.6/32', 'via', '192.0.2.2', 'dev', 'original0', 'table', '42117')
        ip('rule', 'add', 'priority', '100', 'from', '192.0.2.1/32', 'lookup', '42117')
        for name in ('all', 'original0'):
            assert Path('/proc/sys/net/ipv4/conf/' + name + '/rp_filter').read_text().strip() == '1'
        route = json.loads(subprocess.check_output(['ip', '-j', 'route', 'get', '198.18.0.6'], text=True))
        assert route[0]['dev'] == 'capture0', 'competing capture route not selected'
        original_route = json.loads(subprocess.check_output(
            ['ip', '-j', 'route', 'get', '198.18.0.6', 'from', '192.0.2.1'], text=True))
        assert original_route[0]['dev'] == 'original0' and str(original_route[0]['table']) == '42117', original_route
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
        missing = ordinary('original', 'missing0')
        assert missing.returncode != 0, 'missing original interface silently fell back'
    finally:
        if tun is not None:
            os.close(tun)
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
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino:
        parser.error('requires root inside a private Linux network namespace')
    if args.peer:
        peer()
    else:
        if not args.probe or not args.probe.is_file() or not args.uid or args.uid <= 0:
            parser.error('requires a compiled probe and an ordinary uid')
        probe(args.probe.resolve(), args.uid)
