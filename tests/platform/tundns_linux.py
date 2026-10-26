"""Actual resolved/link/journal checks; root only in private mounts and a private netns."""

import argparse
import array
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from tundns_fixture import IsolatedResolver, LocalDnsEndpoint, query_via_tun


def run(*args, **options):
    result = subprocess.run(list(map(str, args)), text=True, capture_output=True, timeout=15,
                            pass_fds=scope_descriptors(), **options)
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


def scope_descriptors():
    return tuple(map(int, os.environ['JC_TEST_HOST_NAMESPACE_FDS'].split(',')))


def probe(binary, *arguments):
    return ['/usr/bin/setpriv', '--bounding-set=-all,+net_admin', str(binary), *arguments]


def exercise(binary, directory, phase, uid, environment):
    folder = directory / phase
    folder.mkdir(mode=0o700)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(10)
    process = subprocess.Popen(probe(binary, '--prepare-isolated', str(child.fileno()), str(folder), phase),
                               pass_fds=(*scope_descriptors(), child.fileno()), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
            hostname = 'witness-' + uuid.uuid4().hex + '.campus.test'
            query_via_tun(device, hostname, peer, uid, environment)
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
            result = subprocess.run(probe(binary, '--recover-isolated', str(folder), metadata['owner']),
                                    text=True, capture_output=True, timeout=15, pass_fds=scope_descriptors())
            if phase == 'restore-dns-pending':
                assert result.returncode == 2 and (folder / 'source.json').is_file(), result.stderr
                assert before == [run('/usr/bin/resolvectl', key, name, env=environment) for key in ('dns', 'domain', 'default-route')]
                os.close(device)
                device = None
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    result = subprocess.run(probe(binary, '--recover-isolated', str(folder), metadata['owner']),
                                            text=True, capture_output=True, timeout=15, pass_fds=scope_descriptors())
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


def exercise_foreign_provider(binary, environment):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent.settimeout(10)
    process = subprocess.Popen(['/usr/bin/unshare', '--net', *probe(binary, '--foreign-provider-isolated', str(child.fileno()))],
                               pass_fds=(*scope_descriptors(), child.fileno()), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    child.close()
    try:
        metadata, descriptors = receive(parent)
        assert not descriptors and type(metadata['index']) is int and metadata['index'] > 1
        run('ip', 'link', 'add', 'dnsforeign0', 'index', metadata['index'], 'type', 'dummy')
        run('ip', 'link', 'set', 'dnsforeign0', 'up')
        baseline = [run('/usr/bin/resolvectl', key, 'dnsforeign0', env=environment) for key in ('dns', 'domain', 'default-route')]
        parent.send(json.dumps({'ready': True}).encode())
        output, error = process.communicate(timeout=15)
        current = [run('/usr/bin/resolvectl', key, 'dnsforeign0', env=environment) for key in ('dns', 'domain', 'default-route')]
        assert process.returncode == 0 and baseline == current, (output, error, baseline, current)
        print(output, end='', flush=True)
        run('ip', 'link', 'delete', 'dnsforeign0')
    finally:
        parent.close()
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    args = parser.parse_args()
    binary = args.probe.resolve(strict=True)
    helper = args.helper.resolve(strict=True)
    assert os.geteuid() == 0 and args.uid != 0
    for kind in ('net', 'mnt'):
        assert os.stat('/proc/thread-self/ns/' + kind) != os.stat('/proc/1/ns/' + kind), 'refusing host namespaces'
    try:
        host = os.stat('/run/dbus/system_bus_socket')
        os.environ['JC_TEST_HOST_BUS_ID'] = str(host.st_dev) + ',' + str(host.st_ino)
    except FileNotFoundError:
        os.environ['JC_TEST_HOST_BUS_ID'] = '0,0'
    descriptors = tuple(os.open('/proc/1/ns/' + kind, os.O_RDONLY) for kind in ('net', 'mnt'))
    os.environ['JC_TEST_HOST_NAMESPACE_FDS'] = ','.join(map(str, descriptors))
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'}
    with tempfile.TemporaryDirectory(prefix='JustConnect-resolved-') as folder:
        root = Path(folder)
        # The ordinary DNS reader executes the staged runtime; recovery journals keep their own private directories.
        root.chmod(0o711)
        os.environ['TMPDIR'] = str(root)
        try:
            # CAP_NET_ADMIN cannot traverse private SDK homes; keep the exact built runtime in this root-owned fixture.
            runtime = root / 'runtime'
            runtime.mkdir()
            dependencies = run('ldd', binary)
            assert 'not found' not in dependencies, dependencies
            for line in dependencies.splitlines():
                if '=>' not in line:
                    continue
                library = Path(line.split('=>', 1)[1].split()[0]).resolve(strict=True)
                if not any(library.is_relative_to(path) for path in ('/usr/lib', '/lib')):
                    shutil.copyfile(library, runtime / line.split('=>', 1)[0].strip())
            staged = runtime / binary.name
            shutil.copyfile(binary, staged)
            staged.chmod(0o755)
            binary = staged
            os.environ['LD_LIBRARY_PATH'] = str(runtime)
            with IsolatedResolver(root / 'resolver', environment) as resolver:
                print(run(*probe(binary, '--absent-isolated')), end='', flush=True)
                resolver.start()
                run('ip', 'link', 'add', 'dnsoriginal0', 'type', 'dummy')
                run('ip', 'link', 'set', 'dnsoriginal0', 'up')
                run('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'dnsoriginal0')
                run('/usr/bin/resolvectl', 'dns', 'dnsoriginal0', '192.0.2.53', env=environment)
                run('/usr/bin/resolvectl', 'domain', 'dnsoriginal0', '~original.test', env=environment)
                baseline = [run('/usr/bin/resolvectl', key, 'dnsoriginal0', env=environment) for key in ('dns', 'domain', 'default-route')]
                with LocalDnsEndpoint('192.0.2.1', 'source-check.original.test') as endpoint:
                    print(run(*probe(binary, '--link-dns-isolated', 'dnsoriginal0', '192.0.2.1', endpoint.port)), end='', flush=True)
                    assert baseline == [run('/usr/bin/resolvectl', key, 'dnsoriginal0', env=environment) for key in ('dns', 'domain', 'default-route')]
                    before_helper = endpoint.queries
                    print(run(sys.executable, '-B', Path(__file__).with_name('networkhelper_linux.py'),
                              '--uid', args.uid, '--helper', helper, '--dns-probe', binary,
                              '--original-dns-port', endpoint.port), end='', flush=True)
                    assert endpoint.queries > before_helper, 'formal helper did not route the original scope to its prepared listener'
                assert baseline == [run('/usr/bin/resolvectl', key, 'dnsoriginal0', env=environment) for key in ('dns', 'domain', 'default-route')]
                exercise_foreign_provider(binary, environment)
                output = run(*probe(binary, '--isolated'))
                print(output, end='', flush=True)
                phases = ('flow', 'apply-domains-pending', 'apply-dns-confirmed', 'restore-dns-pending', 'restore-dns-confirmed')
                for phase in phases:
                    exercise(binary, root, phase, args.uid, environment)
                    assert baseline == [run('/usr/bin/resolvectl', key, 'dnsoriginal0', env=environment) for key in ('dns', 'domain', 'default-route')]
                print('REPORT: ' + json.dumps({'provider': 'actual systemd-resolved on isolated canonical system bus',
                                              'worker_capability': 'CAP_NET_ADMIN only; namespace guard and new-process recovery enforced',
                                              'helper': 'authenticated ordinary fd handoff, actual system query, DNS-first restore and restricted stale-record recovery',
                                              'phases': phases, 'ordinary_uid': args.uid,
                                              'original_interface': 'unchanged; no host route or resolver modification'}), flush=True)
        finally:
            for descriptor in descriptors:
                os.close(descriptor)


if __name__ == '__main__':
    main()
