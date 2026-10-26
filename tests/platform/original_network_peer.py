"""An unprivileged original-network echo peer behind an isolated veth link."""

import os
from contextlib import ExitStack
from pathlib import Path
import pwd
import select
import selectors
import socket
import subprocess
import sys


class OriginalNetworkPeer:
    def __init__(self, uid, environment):
        self.uid, self.environment = uid, environment
        self.process = None
        self.overlay = False

    def start(self):
        self.process = subprocess.Popen(['unshare', '--net', '--', sys.executable, '-B', __file__, '--serve', str(self.uid)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, env=self.environment)
        self._ready('NAMESPACE')
        assert os.stat(f'/proc/{self.process.pid}/ns/net') != os.stat('/proc/thread-self/ns/net')
        for args in [('link', 'add', 'helperorig0', 'type', 'veth', 'peer', 'name', 'helperpeer0'),
                     ('link', 'set', 'helperpeer0', 'netns', str(self.process.pid))]:
            subprocess.run(['ip', *args], env=self.environment, check=True, timeout=3)
        self.process.stdin.write('LINK\n')
        self.process.stdin.flush()
        self._ready('READY')
        status = dict(row.split(':', 1) for row in Path(f'/proc/{self.process.pid}/status').read_text().splitlines())
        assert set(map(int, status['Uid'].split())) == {self.uid}

    def add_overlay(self):
        subprocess.run(['ip', 'link', 'add', 'helperover0', 'type', 'veth', 'peer', 'name', 'helperoverp0'],
                       env=self.environment, check=True, timeout=3)
        self.overlay = True
        for command in [['ip', 'link', 'set', 'helperoverp0', 'netns', str(self.process.pid)],
                        ['ip', 'address', 'add', '192.0.3.1/24', 'dev', 'helperover0'],
                        ['ip', 'link', 'set', 'helperover0', 'up'],
                        ['nsenter', '-t', str(self.process.pid), '-n', '--', 'ip', 'address', 'add', '192.0.3.2/24', 'dev', 'helperoverp0'],
                        ['nsenter', '-t', str(self.process.pid), '-n', '--', 'ip', 'link', 'set', 'helperoverp0', 'up'],
                        ['ip', 'route', 'add', '198.18.0.6/32', 'via', '192.0.3.2', 'dev', 'helperover0']]:
            subprocess.run(command, env=self.environment, check=True, timeout=3)

    def remove_overlay(self):
        if self.overlay:
            subprocess.run(['ip', 'link', 'del', 'helperover0'], env=self.environment, check=True, timeout=3)
            self.overlay = False

    def _ready(self, expected):
        assert select.select([self.process.stdout], [], [], 5)[0], 'original peer did not start'
        assert self.process.stdout.readline().strip() == expected, 'original peer setup failed'

    def close(self):
        self.remove_overlay()
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=5)


def serve(uid):
    assert os.geteuid() == 0 and uid != 0
    for name in ('net', 'mnt'):
        assert os.stat(f'/proc/thread-self/ns/{name}') != os.stat(f'/proc/1/ns/{name}'), 'refusing a host namespace'
    print('NAMESPACE', flush=True)
    assert sys.stdin.readline() == 'LINK\n'
    for args in [('link', 'set', 'helperpeer0', 'up'), ('address', 'add', '192.0.2.2/24', 'dev', 'helperpeer0'),
                 ('address', 'add', '198.18.0.5/32', 'dev', 'helperpeer0'),
                 ('address', 'add', '198.18.0.6/32', 'dev', 'helperpeer0'),
                 ('address', 'add', '198.18.0.7/32', 'dev', 'helperpeer0'),
                 ('route', 'add', 'default', 'via', '192.0.2.1', 'dev', 'helperpeer0')]:
        subprocess.run(['ip', *args], check=True, timeout=3)
    with ExitStack() as sockets, selectors.DefaultSelector() as selector:
        for tcp_address, udp_address in [('198.18.0.7', '198.18.0.6'), ('198.18.0.5', '198.18.0.5')]:
            tcp = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            udp = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            tcp.bind((tcp_address, 80))
            tcp.listen(4)
            udp.bind((udp_address, 53))
            selector.register(tcp, selectors.EVENT_READ, 'accept')
            selector.register(udp, selectors.EVENT_READ, 'udp')
        os.setgroups([])
        os.setgid(pwd.getpwuid(uid).pw_gid)
        os.setuid(uid)
        assert os.getuid() == os.geteuid() == uid
        print('READY', flush=True)
        try:
            while True:
                for key, _ in selector.select():
                    if key.data == 'accept':
                        connection, _ = key.fileobj.accept()
                        connection.settimeout(3)
                        connection.sendall(b'original:')
                        selector.register(connection, selectors.EVENT_READ, 'tcp')
                    elif key.data == 'udp':
                        packet, address = key.fileobj.recvfrom(65536)
                        key.fileobj.sendto(b'original:' + packet, address)
                    else:
                        packet = key.fileobj.recv(65536)
                        if packet:
                            key.fileobj.sendall(packet)
                        else:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
        finally:
            for key in list(selector.get_map().values()):
                key.fileobj.close()


if __name__ == '__main__':
    assert len(sys.argv) == 3 and sys.argv[1] == '--serve'
    serve(int(sys.argv[2]))
