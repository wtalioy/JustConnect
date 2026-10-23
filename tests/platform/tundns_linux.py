"""Actual resolved/link/journal checks; root only in private mounts and a private netns."""

import argparse
import array
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
import tempfile
import time
import uuid


def run(*args, **options):
    result = subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=15, **options)
    assert result.returncode == 0, (list(map(str, args)), result.stdout, result.stderr)
    return result.stdout


def receive(control):
    data, ancillary, flags, _ = control.recvmsg(65536, socket.CMSG_SPACE(array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
    assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
    descriptors = []
    for level, kind, values in ancillary:
        assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
        descriptors.extend(array.array('i', values))
    assert len(descriptors) <= 1 and all(not os.get_inheritable(fd) for fd in descriptors)
    return json.loads(data), descriptors


def dns_reply(fd, packet, expected, peer):
    if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != socket.IPPROTO_UDP:
        return False
    offset = (packet[0] & 15) * 4
    source, target, length, _ = struct.unpack('!4H', packet[offset:offset + 8])
    if target != 53:
        return False
    assert packet[16:20] == socket.inet_aton(peer), 'system query used a DNS server outside the owned peer'
    query = packet[offset + 8:offset + length]
    assert len(query) >= 12 and struct.unpack('!H', query[4:6])[0] == 1
    cursor, labels = 12, []
    while query[cursor]:
        size = query[cursor]
        assert 0 < size <= 63 and cursor + size + 1 < len(query)
        labels.append(query[cursor + 1:cursor + size + 1].decode('ascii'))
        cursor += size + 1
    cursor += 1
    qtype, qclass = struct.unpack('!HH', query[cursor:cursor + 4])
    assert '.'.join(labels) == expected and qtype == qclass == 1
    answer = query[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + query[12:cursor + 4]
    answer += struct.pack('!HHHIH4s', 0xc00c, 1, 1, 60, 4, socket.inet_aton('203.0.113.9'))
    udp = struct.pack('!4H', target, source, 8 + len(answer), 0) + answer
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, socket.IPPROTO_UDP, 0, packet[16:20], packet[12:16])
    checksum = sum(struct.unpack('!10H', header))
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    header = header[:10] + struct.pack('!H', (~checksum) & 0xffff) + header[12:]
    assert os.write(fd, header + udp) == len(header) + len(udp)
    return True


def exercise(binary, directory, phase, uid, environment):
    folder = directory / phase
    folder.mkdir(mode=0o700)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(10)
    process = subprocess.Popen([str(binary), '--prepare-isolated', str(child.fileno()), str(folder), phase],
                               pass_fds=(child.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    child.close()
    device = None
    try:
        metadata, descriptors = receive(parent)
        assert len(descriptors) == 1
        device = descriptors[0]
        name = metadata['device']['interface']
        peer = metadata['device']['configuration']['applied']['ipv4'][0]['peer']
        ready, extra = receive(parent)
        assert not extra
        if phase == 'flow':
            assert ready == {'ready': True}
            account = pwd.getpwuid(uid)
            hostname = 'witness-' + uuid.uuid4().hex + '.campus.test'
            query_code = ('import os,socket; assert os.getuid()==os.geteuid()==' + str(uid)
                          + '; assert int(next(s.split()[1] for s in open("/proc/self/status") if s.startswith("CapEff:")),16)==0'
                          + '; print(socket.getaddrinfo(' + repr(hostname) + ',None,socket.AF_INET,socket.SOCK_STREAM))')
            query = subprocess.Popen([sys.executable, '-c', query_code], env=environment, user=uid, group=account.pw_gid,
                                     extra_groups=(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            packets = 0
            try:
                deadline = time.monotonic() + 8
                while query.poll() is None and time.monotonic() < deadline:
                    if select.select([device], [], [], 0.05)[0]:
                        packets += dns_reply(device, os.read(device, 65536), hostname, peer)
                output, error = query.communicate(timeout=1)
                assert query.returncode == 0 and '203.0.113.9' in output and packets > 0, (output, error)
            finally:
                if query.poll() is None:
                    query.kill()
                    query.communicate(timeout=5)
            parent.send(json.dumps({'done': True}).encode())
            output, errors = process.communicate(timeout=10)
            assert process.returncode == 0, (output, errors)
            print(output, end='', flush=True)
        else:
            assert ready == {'checkpoint': phase}
            process.kill()
            process.communicate(timeout=5)
            assert process.returncode == -signal.SIGKILL
            before = [run('/usr/bin/resolvectl', key, name, env=environment) for key in ('dns', 'domain', 'default-route')]
            result = subprocess.run([str(binary), '--recover-isolated', str(folder), metadata['owner']],
                                    text=True, capture_output=True, timeout=15)
            if phase == 'restore-dns-pending':
                assert result.returncode == 2 and (folder / 'source.json').is_file(), result.stderr
                assert before == [run('/usr/bin/resolvectl', key, name, env=environment) for key in ('dns', 'domain', 'default-route')]
                os.close(device)
                device = None
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    result = subprocess.run([str(binary), '--recover-isolated', str(folder), metadata['owner']],
                                            text=True, capture_output=True, timeout=15)
                    if result.returncode == 0:
                        break
                    time.sleep(0.02)
            assert result.returncode == 0 and not (folder / 'source.json').exists(), (phase, result.stdout, result.stderr)
            print('PASS: actual SIGKILL and authenticated new-process recovery at ' + phase, flush=True)
    finally:
        parent.close()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        if device is not None:
            os.close(device)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    args = parser.parse_args()
    binary = args.probe.resolve(strict=True)
    assert os.geteuid() == 0 and args.uid != 0
    for kind in ('net', 'mnt'):
        assert os.stat('/proc/thread-self/ns/' + kind) != os.stat('/proc/1/ns/' + kind), 'refusing host namespaces'
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'}
    processes = []
    with tempfile.TemporaryDirectory(prefix='JustConnect-resolved-') as folder:
        root = Path(folder)
        os.environ['TMPDIR'] = str(root)
        try:
            run('mount', '--make-rprivate', '/')
            run('mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', '/run')
            Path('/run/dbus').mkdir(mode=0o755)
            Path('/run/systemd/resolve').mkdir(mode=0o755, parents=True)
            resolver_account = pwd.getpwnam('systemd-resolve')
            os.chown('/run/systemd/resolve', resolver_account.pw_uid, resolver_account.pw_gid)
            configuration = root / 'systemd'
            configuration.mkdir(mode=0o755)
            (configuration / 'resolved.conf').write_text('[Resolve]\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\n')
            run('mount', '--bind', configuration, '/etc/systemd')
            config = root / 'dbus.conf'
            config.write_text('<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen>'
                              '<auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/>'
                              '<allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
            daemon_log = (root / 'dbus.log').open('w+')
            processes.append(subprocess.Popen(['/usr/bin/dbus-daemon', '--nofork', '--config-file=' + str(config)],
                                              env=environment, stdout=daemon_log, stderr=subprocess.STDOUT))
            run('ip', 'link', 'set', 'lo', 'up')
            deadline = time.monotonic() + 5
            while not Path('/run/dbus/system_bus_socket').exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            print(run(binary, '--absent-isolated'), end='', flush=True)
            resolved_log = (root / 'resolved.log').open('w+')
            processes.append(subprocess.Popen(['/usr/lib/systemd/systemd-resolved'], env=environment,
                                              stdout=resolved_log, stderr=subprocess.STDOUT))
            while time.monotonic() < deadline:
                ready = subprocess.run(['/usr/bin/resolvectl', 'status'], env=environment, text=True, capture_output=True, timeout=2)
                if ready.returncode == 0:
                    break
                assert processes[-1].poll() is None, (root / 'resolved.log').read_text()
                time.sleep(0.02)
            assert ready.returncode == 0, ready.stderr
            stub = Path('/run/systemd/resolve/stub-resolv.conf')
            assert stub.is_file()
            run('mount', '--bind', stub, '/etc/resolv.conf')
            run('ip', 'link', 'add', 'dnsoriginal0', 'type', 'dummy')
            run('ip', 'link', 'set', 'dnsoriginal0', 'up')
            run('/usr/bin/resolvectl', 'dns', 'dnsoriginal0', '192.0.2.53', env=environment)
            run('/usr/bin/resolvectl', 'domain', 'dnsoriginal0', '~original.test', env=environment)
            baseline = [run('/usr/bin/resolvectl', key, 'dnsoriginal0', env=environment) for key in ('dns', 'domain', 'default-route')]
            output = run(binary, '--isolated')
            print(output, end='', flush=True)
            phases = ('flow', 'apply-domains-pending', 'apply-dns-confirmed', 'restore-dns-pending', 'restore-dns-confirmed')
            for phase in phases:
                exercise(binary, root, phase, args.uid, environment)
                assert baseline == [run('/usr/bin/resolvectl', key, 'dnsoriginal0', env=environment) for key in ('dns', 'domain', 'default-route')]
            print('REPORT: ' + json.dumps({'provider': 'actual systemd-resolved on isolated canonical system bus',
                                          'phases': phases, 'ordinary_uid': args.uid,
                                          'original_interface': 'unchanged; no host route or resolver modification'}), flush=True)
        except BaseException:
            for name in ('dbus.log', 'resolved.log'):
                if (root / name).exists():
                    print(name + ':\n' + (root / name).read_text()[-4000:], file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == '__main__':
    main()
