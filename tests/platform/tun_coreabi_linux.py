"""Verify borrowed TUN fd C ABI attachment with ordinary native sockets in a private namespace."""
import argparse
import array
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
    for name in ('allocator', 'gateway', 'host', 'fd-test', 'adapter'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    args = parser.parse_args()
    if (sys.platform != 'linux' or os.geteuid() != 0 or args.uid <= 0
            or os.path.samestat(os.stat('/proc/self/ns/net'), os.stat('/proc/1/ns/net'))):
        parser.error('requires root in a private Linux network namespace and an ordinary uid')
    paths = [args.allocator, args.gateway, args.host, args.fd_test, args.adapter]
    if not all(path.is_file() for path in paths):
        parser.error('requires compiled allocator, gateway, C ABI/Qt hosts and native fd tests')
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
    descriptor, interface = allocate_unix(args.allocator.resolve())
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
    assert inventory() == before, f'owned interface, route or rule remains: {interface}'
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    descriptor = None
    process = None
    try:
        parent.settimeout(75)
        with tempfile.TemporaryDirectory(prefix='jc-qt-tun-runtime-') as runtime:
            os.chown(runtime, args.uid, user.pw_gid)
            env = dict(os.environ, JC_NATIVE_TUN_HOST=str(args.adapter.resolve()),
                       JC_NATIVE_TUN_FD=str(child.fileno()), XDG_RUNTIME_DIR=runtime)
            process = subprocess.Popen([str(args.gateway.resolve()), '-test.v', '-test.timeout', '75s',
                                        '-test.run', '^TestNativeTUNHost$'], env=env, user=args.uid,
                                       group=user.pw_gid, extra_groups=[], pass_fds=(child.fileno(),),
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            child.close()
            for _ in range(2):
                for _ in range(2):
                    assert parent.recv(1) == b'A', 'Qt did not request its owned device'
                    if descriptor is None:
                        descriptor, interface = allocate_unix(args.allocator.resolve())
                        os.set_blocking(descriptor, False)
                    # The fixture allocator owns the device MTU; read it from the kernel.
                    link = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'dev', interface], text=True, timeout=5))
                    parent.sendmsg([str(link[0]['mtu']).encode()],
                                   [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [descriptor]))])
                assert parent.recv(1) == b'R', 'Qt did not release its session'
                os.close(descriptor)
                descriptor = None
                assert inventory() == before, f'Qt retained device or network state: {interface}'
                parent.sendall(b'R')
            output, _ = process.communicate(timeout=10)
            print(output, end='', flush=True)
            assert process.returncode == 0, 'Qt native gateway failed'
    finally:
        parent.close()
        child.close()
        if process is not None and process.stdout and not process.stdout.closed:
            if process.poll() is None:
                process.kill()
            output, _ = process.communicate(timeout=5)
            print(output, end='', flush=True)
        if descriptor is not None:
            os.close(descriptor)
    assert inventory() == before, 'Qt native fixture left owned network state'
    print('PASS: ordinary caller uses actual C ABI TUN duplicate; owned device disappears after all references close', flush=True)


if __name__ == '__main__':
    main()
