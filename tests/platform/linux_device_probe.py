"""S1-06 kernel/fd probe; run as root in a disposable network namespace."""

import argparse
import fcntl
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import struct
import subprocess
import time


def exchange(fd):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3)
        udp.bind(('198.18.0.1', 0))
        local_port = udp.getsockname()[1]
        udp.sendto(b'justconnect-out', ('198.18.0.2', 54321))
        deadline = time.monotonic() + 3
        while True:
            ready, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
            assert ready, 'no outbound packet on transferred TUN fd'
            packet = os.read(fd, 65536)
            if packet[0] >> 4 != 4 or packet[9] != socket.IPPROTO_UDP:
                continue
            offset = (packet[0] & 15) * 4
            if packet[offset + 8:] != b'justconnect-out':
                continue
            assert packet[12:20] == socket.inet_aton('198.18.0.1') + socket.inet_aton('198.18.0.2')
            assert struct.unpack('!HH', packet[offset:offset + 4]) == (local_port, 54321)
            break

        payload = b'justconnect-in'
        reply_udp = struct.pack('!HHHH', 54321, local_port, 8 + len(payload), 0) + payload
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(reply_udp), 1, 0, 64,
                             socket.IPPROTO_UDP, 0, socket.inet_aton('198.18.0.2'),
                             socket.inet_aton('198.18.0.1'))
        checksum = sum(struct.unpack('!10H', header))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        header = header[:10] + struct.pack('!H', (~checksum) & 0xffff) + header[12:]
        packet = header + reply_udp
        assert os.write(fd, packet) == len(packet)
        assert udp.recvfrom(65536) == (payload, ('198.18.0.2', 54321))


def probe(uid, gid, crash):
    name = 'jcprobe0'
    try:
        socket.if_nametoindex(name)
    except OSError:
        pass
    else:
        raise AssertionError('test interface already exists')
    fd = os.open('/dev/net/tun', os.O_RDWR | os.O_CLOEXEC)
    parent, child = socket.socketpair()
    pid = None
    reaped = False
    try:
        fcntl.ioctl(fd, 0x400454ca, struct.pack('16sH22x', name.encode(), 0x1001))
        subprocess.run(['ip', 'address', 'add', '198.18.0.1/30', 'dev', name], check=True)
        subprocess.run(['ip', 'link', 'set', name, 'up'], check=True)
        pid = os.fork()
        if pid == 0:
            try:
                parent.close()
                os.close(fd)
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
                assert os.geteuid() == uid and uid != 0
                status = Path('/proc/self/status').read_text()
                caps = next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:'))
                assert int(caps, 16) == 0, 'receiver retained capabilities'
                child.settimeout(5)
                message, fds, _, _ = socket.recv_fds(child, 1, 1)
                assert message == b'F' and len(fds) == 1
                received = fds[0]
                exchange(received)
                if crash:
                    child.sendall(b'K')
                    child.recv(1)  # Parent kills this process with its fd still open.
                    raise AssertionError('crash receiver unexpectedly resumed')
                os.close(received)
                child.sendall(b'K')
                os._exit(0)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(1)

        child.close()
        parent.settimeout(8)
        socket.send_fds(parent, [b'F'], [fd])
        os.close(fd)
        fd = None
        assert parent.recv(1) == b'K', 'unprivileged receiver failed'
        if crash:
            os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        reaped = True
        if crash:
            assert os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
        else:
            assert os.waitstatus_to_exitcode(status) == 0
        try:
            socket.if_nametoindex(name)
        except OSError:
            pass
        else:
            raise AssertionError('TUN survived its final fd')
        routes = subprocess.check_output(['ip', '-j', 'route', 'show'], text=True)
        assert name not in routes, 'TUN route survived device removal'
        print(f'PASS: SCM_RIGHTS -> uid={uid}, capabilities=0, UDP both ways, '
              f'{"SIGKILL" if crash else "normal close"}, device/route removed', flush=True)
    finally:
        if fd is not None:
            os.close(fd)
        parent.close()
        child.close()
        if pid is not None and not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True, help='ordinary receiving user')
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid <= 0:
        parser.error('requires root and a non-root receiving uid')
    if os.stat('/proc/self/ns/net').st_ino == os.stat('/proc/1/ns/net').st_ino:
        parser.error('refusing to run in the host network namespace; use unshare --net')
    user = pwd.getpwuid(args.uid)
    for crash in (False, True):
        probe(user.pw_uid, user.pw_gid, crash)
