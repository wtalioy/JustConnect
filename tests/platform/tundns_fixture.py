"""Shared actual system-resolver query and TUN reply fixture."""

import json
import os
from pathlib import Path
import pwd
import select
import socket
import struct
import subprocess
import sys
import time
import threading

from dns_fixture import dns_answer


class IsolatedResolver:
    def __init__(self, root, environment):
        self.root, self.environment = Path(root), environment
        self.socket = self.root / 'bus.sock'
        self.processes, self.logs = [], []
        self.pinned = []

    def run(self, *arguments):
        result = subprocess.run(list(map(str, arguments)), env=self.environment, text=True,
                                capture_output=True, timeout=15)
        assert result.returncode == 0, (arguments, result.stdout, result.stderr)
        return result.stdout

    def __enter__(self):
        assert os.geteuid() == 0
        for kind in ('net', 'mnt'):
            assert os.stat('/proc/thread-self/ns/' + kind) != os.stat('/proc/1/ns/' + kind), 'refusing host namespaces'
        self.root.mkdir(mode=0o755)
        self.loopback_up = 'UP' in json.loads(self.run('ip', '-j', 'link', 'show', 'lo'))[0]['flags']
        try:
            self.run('mount', '--make-rprivate', '/')
            manager_booted = Path('/run/systemd/system').is_dir()
            # Pin transports in this mount namespace before hiding /run.
            for name in ('systemd/private', 'log/journal'):
                source, pinned = Path('/run') / name, self.root / ('host-' + name.replace('/', '-'))
                if not source.exists():
                    continue
                if source.is_dir():
                    pinned.mkdir()
                else:
                    pinned.touch()
                self.run('mount', '--bind', source, pinned)
                self.pinned.append((name, pinned))
            self.run('mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run')
            for name in ('dbus', 'systemd/resolve'):
                (Path('/run') / name).mkdir(mode=0o755, parents=True)
            # Keep the real system-manager transport/journal available while DNS gets its own bus.
            for name, source in self.pinned:
                target = Path('/run') / name
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                if source.is_dir():
                    target.mkdir()
                else:
                    target.touch()
                self.run('mount', '--bind', source, target)
                original, mounted = source.stat(), target.stat()
                assert (original.st_dev, original.st_ino) == (mounted.st_dev, mounted.st_ino)
            if manager_booted:
                Path('/run/systemd/system').mkdir()
            account = pwd.getpwnam('systemd-resolve')
            os.chown('/run/systemd/resolve', account.pw_uid, account.pw_gid)
            configuration = self.root / 'systemd'
            configuration.mkdir()
            (configuration / 'resolved.conf').write_text('[Resolve]\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\n')
            self.run('mount', '--bind', configuration, '/etc/systemd')
            config = self.root / 'dbus.conf'
            config.write_text('<busconfig><type>system</type><listen>unix:path=' + str(self.socket) + '</listen>'
                              '<auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/>'
                              '<allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
            log = (self.root / 'dbus.log').open('w+')
            self.logs.append(log)
            self.processes.append(subprocess.Popen(['/usr/bin/dbus-daemon', '--nofork', '--config-file=' + str(config)],
                                                  env=self.environment, stdout=log, stderr=subprocess.STDOUT))
            self.deadline = time.monotonic() + 5
            while not self.socket.exists() and time.monotonic() < self.deadline:
                assert self.processes[-1].poll() is None
                time.sleep(0.02)
            assert self.socket.is_socket()
            Path('/run/dbus/system_bus_socket').touch()
            self.run('mount', '--bind', self.socket, '/run/dbus/system_bus_socket')
            self.run('ip', 'link', 'set', 'lo', 'up')
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def start(self):
        log = (self.root / 'resolved.log').open('w+')
        self.logs.append(log)
        self.processes.append(subprocess.Popen(['/usr/lib/systemd/systemd-resolved'], env=self.environment,
                                              stdout=log, stderr=subprocess.STDOUT))
        ready = None
        while time.monotonic() < self.deadline:
            ready = subprocess.run(['/usr/bin/resolvectl', 'status'], env=self.environment, text=True,
                                   capture_output=True, timeout=2)
            if ready.returncode == 0:
                break
            assert self.processes[-1].poll() is None
            time.sleep(0.02)
        assert ready and ready.returncode == 0, ready
        stub = Path('/run/systemd/resolve/stub-resolv.conf')
        assert stub.is_file()
        self.run('mount', '--bind', stub, '/etc/resolv.conf')

    def __exit__(self, error_type, error, traceback):
        for process in reversed(self.processes):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for log in self.logs:
            log.close()
        for _, path in reversed(self.pinned):
            self.run('umount', path)
        if not self.loopback_up:
            self.run('ip', 'link', 'set', 'lo', 'down')
        if error_type:
            for name in ('dbus.log', 'resolved.log'):
                path = self.root / name
                if path.exists():
                    print(name + ':\n' + path.read_text()[-4000:], file=sys.stderr)


class LocalDnsEndpoint:
    """A DNS listener at an already assigned test address and a kernel-selected port."""
    def __init__(self, address, hostname):
        self.address, self.hostname = address, hostname
        self.stopped, self.errors = threading.Event(), []
        self.queries = 0

    def __enter__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((self.address, 0))
            self.socket.settimeout(0.1)
            self.port = self.socket.getsockname()[1]
            self.thread = threading.Thread(target=self.serve)
            self.thread.start()
            return self
        except BaseException:
            self.socket.close()
            raise

    def serve(self):
        try:
            while not self.stopped.is_set():
                try:
                    query, peer = self.socket.recvfrom(65535)
                except socket.timeout:
                    continue
                reply = dns_answer(query, self.hostname, ignore_unrelated=True)
                if reply is not None:
                    self.socket.sendto(reply, peer)
                    self.queries += 1
        except Exception as error:
            self.errors.append(error)

    def __exit__(self, kind, error, traceback):
        self.stopped.set()
        self.thread.join(timeout=2)
        self.socket.close()
        if kind is None:
            assert not self.thread.is_alive() and not self.errors, self.errors


class OriginalDnsServer:
    """An actual UDP DNS server on the fixture's original interface."""
    def __init__(self, resolver, interface, address="192.0.2.53", answers=None):
        self.resolver, self.interface = resolver, interface
        self.address, self.answers = address, dict(answers or {})
        self.queries, self.errors = [], []
        self.stopped = threading.Event()

    def __enter__(self):
        self.resolver.run('ip', 'address', 'add', self.address + '/32', 'dev', self.interface)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((self.address, 53))
            self.socket.settimeout(0.1)
            self.thread = threading.Thread(target=self.serve)
            self.thread.start()
            return self
        except BaseException:
            self.socket.close()
            self.resolver.run('ip', 'address', 'del', self.address + '/32', 'dev', self.interface)
            raise

    def serve(self):
        while not self.stopped.is_set():
            try:
                query, sender = self.socket.recvfrom(65536)
            except socket.timeout:
                continue
            try:
                for hostname in ('public.test', 'host.original.test', *self.answers):
                    labels = b''.join(bytes([len(label)]) + label.encode('ascii') for label in hostname.split('.')) + b'\0'
                    if query[12:].startswith(labels):
                        answer = dns_answer(query, hostname, **({'ipv4': self.answers[hostname]} if hostname in self.answers else {}))
                        self.socket.sendto(answer, sender)
                        self.queries.append(hostname)
                        break
                else:
                    raise AssertionError('original resolver received an unexpected query')
            except BaseException as error:
                self.errors.append(str(error))
                return

    def __exit__(self, kind, error, traceback):
        self.stopped.set()
        self.thread.join(timeout=2)
        self.socket.close()
        self.resolver.run('ip', 'address', 'del', self.address + '/32', 'dev', self.interface)
        if kind is None:
            assert not self.thread.is_alive() and not self.errors, self.errors


def dns_reply(fd, packet, expected, peer, framing=b''):
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != socket.IPPROTO_UDP:
        return False
    offset = (packet[0] & 15) * 4
    source, target, length, _ = struct.unpack('!4H', packet[offset:offset + 8])
    if target != 53:
        return False
    assert packet[16:20] == socket.inet_aton(peer), 'system query used a DNS server outside the owned peer'
    # Darwin's system resolver also sends interface discovery queries to this peer.
    answer = dns_answer(packet[offset + 8:offset + length], expected, ignore_unrelated=bool(framing))
    if answer is None:
        return False
    udp = struct.pack('!4H', target, source, 8 + len(answer), 0) + answer
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, socket.IPPROTO_UDP, 0, packet[16:20], packet[12:16])
    checksum = sum(struct.unpack('!10H', header))
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    header = header[:10] + struct.pack('!H', (~checksum) & 0xffff) + header[12:]
    assert os.write(fd, framing + header + udp) == len(framing) + len(header) + len(udp)
    return True


def query_via_tun(device, hostname, peer, uid, environment):
    account = pwd.getpwuid(uid)
    code = ('import os,socket; assert os.getuid()==os.geteuid()==' + str(uid)
            + ('; assert int(next(s.split()[1] for s in open("/proc/self/status") if s.startswith("CapEff:")),16)==0' if sys.platform == 'linux' else '')
            + ('; assert all(r[4][0].startswith("127.") for r in socket.getaddrinfo("localhost",None,socket.AF_INET))' if sys.platform == 'darwin' else '')
            + '; print(socket.getaddrinfo(' + repr(hostname) + ',None,socket.AF_INET,socket.SOCK_STREAM))')
    assert os.geteuid() in (0, uid)
    identity = dict(user=uid, group=account.pw_gid, extra_groups=()) if os.geteuid() == 0 else {}
    query = subprocess.Popen([sys.executable, '-c', code], env=environment, **identity,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    packets = 0
    try:
        deadline = time.monotonic() + 8
        while query.poll() is None and time.monotonic() < deadline:
            if select.select([device], [], [], 0.05)[0]:
                packet = os.read(device, 65536)
                framing = struct.pack('!I', socket.AF_INET) if sys.platform == 'darwin' else b''
                if framing and not packet.startswith(framing):
                    continue
                packets += dns_reply(device, packet[len(framing):], hostname, peer, framing)
        output, error = query.communicate(timeout=1)
        assert query.returncode == 0 and '203.0.113.9' in output and packets > 0, (output, error)
    finally:
        if query.poll() is None:
            query.kill()
            query.communicate(timeout=5)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Ordinary Darwin system resolver through an inherited owned utun')
    parser.add_argument('--device', type=int, required=True)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--peer', required=True)
    args = parser.parse_args()
    assert sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0
    query_via_tun(args.device, args.hostname, args.peer, os.getuid(), os.environ.copy())
    print('PASS: ordinary getaddrinfo and localhost through the owned supplemental DNS path')
