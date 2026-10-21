"""S1-06 kernel/fd probe; isolated Linux namespace or disposable macOS runner only."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import struct
import subprocess
import sys
import time


def exchange(fd, destination):
    prefix = struct.pack('!I', socket.AF_INET) if sys.platform == 'darwin' else b''
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3)
        udp.bind(('198.18.0.1', 0))
        local_port = udp.getsockname()[1]
        udp.sendto(b'justconnect-out', (destination, 54321))
        deadline = time.monotonic() + 3
        while True:
            ready, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
            assert ready, 'no outbound packet on transferred TUN fd'
            packet = os.read(fd, 65536)
            if prefix:
                if not packet.startswith(prefix):
                    continue
                packet = packet[len(prefix):]
            if len(packet) < 20 or packet[0] >> 4 != 4 or packet[9] != socket.IPPROTO_UDP:
                continue
            offset = (packet[0] & 15) * 4
            if packet[offset + 8:] != b'justconnect-out':
                continue
            assert packet[12:20] == socket.inet_aton('198.18.0.1') + socket.inet_aton(destination)
            assert struct.unpack('!HH', packet[offset:offset + 4]) == (local_port, 54321)
            break

        payload = b'justconnect-in'
        reply_udp = struct.pack('!HHHH', 54321, local_port, 8 + len(payload), 0) + payload
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(reply_udp), 1, 0, 64,
                             socket.IPPROTO_UDP, 0, socket.inet_aton(destination),
                             socket.inet_aton('198.18.0.1'))
        checksum = sum(struct.unpack('!10H', header))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        header = header[:10] + struct.pack('!H', (~checksum) & 0xffff) + header[12:]
        packet = prefix + header + reply_udp
        assert os.write(fd, packet) == len(packet)
        assert udp.recvfrom(65536) == (payload, (destination, 54321))


def receive(control_fd, uid, gid, crash):
    assert os.getuid() == os.geteuid() == uid and uid != 0
    assert os.getgid() == os.getegid() == gid and gid != 0
    if sys.platform == 'darwin':
        import ctypes
        # Python's macOS getgroups reports directory membership, not native process groups.
        getgroups = ctypes.CDLL(None, use_errno=True).getgroups
        getgroups.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
        getgroups.restype = ctypes.c_int
        groups = (ctypes.c_uint32 * 16)()
        count = getgroups(len(groups), groups)
        assert 0 <= count <= len(groups), 'cannot read native process groups'
        assert set(groups[:count]) == {gid}, f'receiver retained native groups: {list(groups[:count])}'
    else:
        assert os.getgroups() == [], 'receiver retained supplementary groups'
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise AssertionError('receiver could restore root privileges')
    if sys.platform == 'linux':
        status = Path('/proc/self/status').read_text()
        caps = next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:'))
        assert int(caps, 16) == 0, 'receiver retained capabilities'
    with socket.socket(fileno=control_fd) as control:
        control.settimeout(5)
        control.sendall(b'R')
        message, fds, _, _ = socket.recv_fds(control, 1, 1)
        assert message == b'F' and len(fds) == 1
        received = fds[0]
        for destination, confirmation in [('198.18.0.2', b'C'), ('198.18.0.6', b'E')]:
            exchange(received, destination)
            control.sendall(confirmation)
        if crash:
            control.sendall(b'K')
            control.recv(1)  # Parent kills this process with its fd still open.
            raise AssertionError('crash receiver unexpectedly resumed')
        os.close(received)
        control.sendall(b'K')


def probe(uid, gid, crash):
    name = 'jcprobe0'
    if sys.platform == 'darwin':
        for destination in ('198.18.0.2', '198.18.0.6'):
            route = subprocess.check_output(['/sbin/route', '-n', 'get', destination], text=True, timeout=5)
            assert any(line.split() == ['destination:', 'default'] for line in route.splitlines()), 'test destination already has a specific route'
    try:
        socket.if_nametoindex(name)
    except OSError:
        pass
    else:
        raise AssertionError('test interface already exists')
    if sys.platform == 'darwin':
        with socket.socket(socket.AF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL) as control:
            info = fcntl.ioctl(control.fileno(), 0xc0644e03, struct.pack('I96s', 0, b'com.apple.net.utun_control'))
            control.connect((struct.unpack_from('I', info)[0], 0))
            name = control.getsockopt(socket.SYSPROTO_CONTROL, 2, 16).split(b'\0', 1)[0].decode('ascii')
            assert name.startswith('utun') and name[4:].isdigit()
            fd = control.detach()
    else:
        fd = os.open('/dev/net/tun', os.O_RDWR | os.O_CLOEXEC)
    parent, child = socket.socketpair()
    receiver = None
    try:
        if sys.platform == 'darwin':
            subprocess.run(['/sbin/ifconfig', name, 'inet', '198.18.0.1', '198.18.0.2', 'netmask', '255.255.255.252', 'up'], check=True, timeout=5)
            subprocess.run(['/sbin/route', '-n', 'add', '-host', '198.18.0.6', '-interface', name], check=True, timeout=5)
            route = subprocess.check_output(['/sbin/route', '-n', 'get', '198.18.0.6'], text=True, timeout=5)
            assert any(line.split() == ['interface:', name] for line in route.splitlines()), 'owned host route was not applied'
        else:
            fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH22x', name.encode(), 0x1001))
            subprocess.run(['ip', 'address', 'add', '198.18.0.1/30', 'dev', name], check=True)
            subprocess.run(['ip', 'link', 'set', name, 'up'], check=True)
            subprocess.run(['ip', 'route', 'add', '198.18.0.6/32', 'dev', name], check=True)
            route = json.loads(subprocess.check_output(['ip', '-j', 'route', 'get', '198.18.0.6'], text=True))
            assert route[0]['dev'] == name, 'owned host route was not applied'
        command = [sys.executable, str(Path(__file__).resolve()), '--uid', str(uid),
                   '--receive-fd', str(child.fileno())]
        if crash:
            command.append('--crash')
        # Exec after dropping privileges: Python/native runtime state cannot cross fork safely on macOS.
        receiver = subprocess.Popen(command, pass_fds=(child.fileno(),), user=uid, group=gid,
                                    extra_groups=[gid] if sys.platform == 'darwin' else [])
        child.close()
        deadline = time.monotonic() + 8

        def acknowledge(expected, stage):
            remaining = deadline - time.monotonic()
            assert remaining > 0, f'receiver budget exhausted at {stage}'
            parent.settimeout(remaining)
            try:
                actual = parent.recv(1)
            except TimeoutError as error:
                raise TimeoutError(f'unprivileged receiver stalled at {stage}') from error
            assert actual == expected, f'unprivileged receiver failed at {stage}: {actual!r}'

        acknowledge(b'R', 'privilege verification')
        socket.send_fds(parent, [b'F'], [fd])
        os.close(fd)
        fd = None
        acknowledge(b'C', 'connected route exchange')
        acknowledge(b'E', 'explicit route exchange')
        acknowledge(b'K', 'final fd ownership')
        if crash:
            receiver.kill()
        status = receiver.wait(timeout=5)
        assert status == (-signal.SIGKILL if crash else 0), f'unexpected receiver exit: {status}'
        deadline = time.monotonic() + 5
        while True:
            try:
                socket.if_nametoindex(name)
            except OSError:
                break
            assert time.monotonic() < deadline, 'TUN survived its final fd'
            time.sleep(0.05)
        command = ['/usr/sbin/netstat', '-rn'] if sys.platform == 'darwin' else ['ip', '-j', 'route', 'show']
        routes = subprocess.check_output(command, text=True, timeout=5)
        remaining = routes.split() if sys.platform == 'darwin' else routes
        assert name not in remaining, 'TUN route survived device removal'
        print(f'PASS: SCM_RIGHTS -> uid={uid}, unprivileged, UDP connected/explicit routes both ways, '
              f'{"SIGKILL" if crash else "normal close"}, device/route removed', flush=True)
    finally:
        if fd is not None:
            os.close(fd)
        parent.close()
        child.close()
        if receiver is not None and receiver.poll() is None:
            receiver.kill()
            receiver.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True, help='ordinary receiving user')
    parser.add_argument('--receive-fd', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--crash', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.receive_fd is not None:
        receive(args.receive_fd, args.uid, pwd.getpwuid(args.uid).pw_gid, args.crash)
        sys.exit(0)
    if os.geteuid() != 0 or args.uid <= 0:
        parser.error('requires root and a non-root receiving uid')
    if sys.platform == 'linux':
        if os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino:
            parser.error('refusing to run in the host network namespace; use unshare --net')
    elif sys.platform == 'darwin':
        if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS':
            parser.error('macOS device probe requires a disposable GitHub runner')
    else:
        parser.error('unsupported device probe platform')
    user = pwd.getpwuid(args.uid)
    for crash in (False, True):
        probe(user.pw_uid, user.pw_gid, crash)
