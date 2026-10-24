"""Verify borrowed TUN fd C ABI attachment with ordinary native sockets in an isolated namespace or disposable macOS runner."""
import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import time
from unix_device_probe import allocate_unix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('allocator', 'gateway', 'host', 'fd-test'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid <= 0:
        parser.error('requires root and an ordinary uid')
    if sys.platform == 'linux':
        if os.path.samestat(os.stat('/proc/self/ns/net'), os.stat('/proc/1/ns/net')):
            parser.error('requires a private Linux network namespace')
    elif sys.platform == 'darwin':
        if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS':
            parser.error('requires the disposable macOS CI runner')
        for destination in ('198.18.0.2', '198.18.0.6'):
            route = subprocess.check_output(['/sbin/route', '-n', 'get', destination], text=True, timeout=5)
            assert any(line.split() == ['destination:', 'default'] for line in route.splitlines()), 'test destination already has a specific route'
    else:
        parser.error('requires Linux or macOS')
    paths = [args.allocator, args.gateway, args.host, args.fd_test]
    if not all(path.is_file() for path in paths):
        parser.error('requires compiled allocator, gateway, formal C ABI host and native fd tests')
    user = pwd.getpwuid(args.uid)
    if sys.platform == 'linux':
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=5)
    def inventory():
        facts = [socket.if_nameindex()]
        if sys.platform == 'darwin':
            for family in ('inet', 'inet6'):
                output = subprocess.check_output(['/usr/sbin/netstat', '-rn', '-f', family], text=True, timeout=5)
                facts.append([line.split() for line in output.splitlines() if line.split()[:1] == ['default']])
            facts.append(subprocess.check_output(['/usr/sbin/scutil', '--dns'], text=True, timeout=5))
            return facts
        for family in ('-4', '-6'):
            for kind in ('route', 'rule'):
                command = ['ip', '-N', '-j', family, kind, 'show']
                if kind == 'route':
                    command += ['table', 'all']
                facts.append(json.loads(subprocess.check_output(command, text=True, timeout=5)))
        return facts
    before = inventory()
    if sys.platform == 'linux':
        subprocess.run([str(args.fd_test.resolve()), '-test.v', '-test.run', '^TestNativeLinuxTUNDescriptors$'],
                       env=dict(os.environ, JC_TEST_TUN_NATIVE='1'), check=True, timeout=30)
    descriptor, interface, cleanup_allocator = allocate_unix(args.allocator.resolve())
    try:
        os.set_blocking(descriptor, False)
        if sys.platform == 'darwin':
            subprocess.run(['/sbin/route', '-n', 'add', '-host', '198.18.0.6', '-interface', interface], check=True, timeout=5)
            subprocess.run([str(args.fd_test.resolve()), '-test.v', '-test.timeout', '30s'],
                           env=dict(os.environ, JC_TEST_TUN_FD=str(descriptor)),
                           user=args.uid, group=user.pw_gid, extra_groups=[user.pw_gid],
                           pass_fds=(descriptor,), check=True, timeout=35)
        with tempfile.TemporaryDirectory(prefix='jc-tun-runtime-') as runtime:
            os.chown(runtime, args.uid, user.pw_gid)
            env = dict(os.environ, JC_NATIVE_TUN_HOST=str(args.host.resolve()),
                       JC_NATIVE_TUN_FD=str(descriptor), QT_QPA_PLATFORM='offscreen', XDG_RUNTIME_DIR=runtime)
            subprocess.run([str(args.gateway.resolve()), '-test.v', '-test.timeout', '75s', '-test.run', '^TestNativeTUNHost$'],
                           env=env, user=args.uid, group=user.pw_gid, extra_groups=[user.pw_gid] if sys.platform == 'darwin' else [], pass_fds=(descriptor,),
                           check=True, timeout=80)
    finally:
        os.close(descriptor)
        cleanup_allocator()
    if sys.platform == 'darwin':
        deadline = time.monotonic() + 5
        while True:
            try:
                socket.if_nametoindex(interface)
            except OSError:
                break
            assert time.monotonic() < deadline, 'utun survived its final fd'
            time.sleep(0.05)
        for destination in ('198.18.0.2', '198.18.0.6'):
            route = subprocess.check_output(['/sbin/route', '-n', 'get', destination], text=True, timeout=5)
            assert any(line.split() == ['destination:', 'default'] for line in route.splitlines()), 'owned host route remains'
    assert inventory() == before, f'owned interface, route or rule remains: {interface}'
    print('PASS: ordinary caller uses actual C ABI TUN duplicate; owned device disappears after all references close', flush=True)


if __name__ == '__main__':
    main()
