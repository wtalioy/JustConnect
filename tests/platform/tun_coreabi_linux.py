"""Verify borrowed TUN fd C ABI attachment with ordinary native sockets in a private namespace."""
import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
from unix_device_probe import allocate_unix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('allocator', 'gateway', 'host', 'fd-test'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    args = parser.parse_args()
    if (sys.platform != 'linux' or os.geteuid() != 0 or args.uid <= 0
            or os.path.samestat(os.stat('/proc/self/ns/net'), os.stat('/proc/1/ns/net'))):
        parser.error('requires root in a private Linux network namespace and an ordinary uid')
    paths = [args.allocator, args.gateway, args.host, args.fd_test]
    if not all(path.is_file() for path in paths):
        parser.error('requires compiled allocator, gateway, formal C ABI host and native fd tests')
    user = pwd.getpwuid(args.uid)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, timeout=5)
    def inventory():
        facts = [socket.if_nameindex()]
        for family in ('-4', '-6'):
            for kind in ('route', 'rule'):
                command = ['ip', '-N', '-j', family, kind, 'show']
                if kind == 'route':
                    command += ['table', 'all']
                facts.append(json.loads(subprocess.check_output(command, text=True, timeout=5)))
        return facts
    before = inventory()
    subprocess.run([str(args.fd_test.resolve()), '-test.v', '-test.run', '^TestNativeLinuxTUNDescriptors$'],
                   env=dict(os.environ, JC_TEST_TUN_NATIVE='1'), check=True, timeout=30)
    descriptor, interface, cleanup_allocator = allocate_unix(args.allocator.resolve())
    try:
        os.set_blocking(descriptor, False)
        with tempfile.TemporaryDirectory(prefix='jc-tun-runtime-') as runtime:
            os.chown(runtime, args.uid, user.pw_gid)
            env = dict(os.environ, JC_NATIVE_TUN_HOST=str(args.host.resolve()),
                       JC_NATIVE_TUN_FD=str(descriptor), QT_QPA_PLATFORM='offscreen', XDG_RUNTIME_DIR=runtime)
            subprocess.run([str(args.gateway.resolve()), '-test.v', '-test.timeout', '75s', '-test.run', '^TestNativeTUNHost$'],
                           env=env, user=args.uid, group=user.pw_gid, extra_groups=[], pass_fds=(descriptor,),
                           check=True, timeout=80)
    finally:
        os.close(descriptor)
        cleanup_allocator()
    assert inventory() == before, f'owned interface, route or rule remains: {interface}'
    print('PASS: ordinary caller uses actual C ABI TUN duplicate; owned device disappears after all references close', flush=True)


if __name__ == '__main__':
    main()
