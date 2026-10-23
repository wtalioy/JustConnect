"""Actual ordinary-user/helper IPC and durable recovery, inside a private netns only."""

import argparse
import array
import json
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import tempfile
import uuid

from unix_device_probe import exchange


def encode(value):
    return json.dumps(value, separators=(',', ':')).encode()


def user_agent(control, uid):
    account = pwd.getpwuid(uid)
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(uid)
    assert os.geteuid() == uid and int(next(row.split()[1] for row in Path('/proc/self/status').read_text().splitlines()
                                          if row.startswith('CapEff:')), 16) == 0
    listener = channel = None
    descriptors = []
    try:
        while True:
            command = json.loads(control.recv(65536))
            operation = command['operation']
            answer = {}
            if operation == 'listen':
                if channel:
                    channel.close()
                    channel = None
                if listener:
                    listener.close()
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                listener.bind(f'\0JustConnect.network.{uid}.{command["owner"]}')
                listener.listen(1)
                listener.settimeout(10)
            elif operation == 'accept':
                channel, _ = listener.accept()
                channel.settimeout(15)
                assert struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[:2] == (command['pid'], 0)
            elif operation == 'listener-empty':
                listener.settimeout(0.05)
                try:
                    unexpected, _ = listener.accept()
                except socket.timeout:
                    pass
                else:
                    unexpected.close()
                    raise AssertionError('uninstalled helper reached the privileged channel')
                finally:
                    listener.settimeout(10)
            elif operation == 'send':
                if command.get('descriptor'):
                    with open('/dev/null', 'rb') as extra:
                        channel.sendmsg([encode(command['packet'])], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [extra.fileno()]))])
                else:
                    channel.sendall(encode(command['packet']))
            elif operation == 'receive':
                data, ancillary, flags, _ = channel.recvmsg(65536, socket.CMSG_SPACE(16 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
                assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                incoming = []
                for level, kind, payload in ancillary:
                    assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                    incoming.extend(array.array('i', payload))
                for fd in incoming:
                    assert not os.get_inheritable(fd)
                descriptors.extend(incoming)
                answer = {'packet': json.loads(data) if data else None, 'descriptors': len(incoming)}
            elif operation == 'exchange':
                assert len(descriptors) == 1
                exchange(descriptors[0], '198.18.4.7')
            elif operation == 'disconnect':
                channel.close()
                channel = None
            elif operation == 'close-descriptors':
                for fd in descriptors:
                    os.close(fd)
                descriptors.clear()
            elif operation == 'exit':
                control.sendall(encode({}))
                return
            else:
                raise AssertionError(operation)
            control.sendall(encode(answer))
    except BaseException as error:
        control.sendall(encode({'error': repr(error)}))
        raise
    finally:
        for fd in descriptors:
            os.close(fd)
        if channel:
            channel.close()
        if listener:
            listener.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--installed', action='store_true', help='exercise the actual installed entry in private mount/network namespaces')
    parser.add_argument('--uninstalled-helper', type=Path, help='installed-entry negative fixture with the same binary at another path')
    args = parser.parse_args()
    assert os.geteuid() == 0 and args.uid != 0
    assert os.stat('/proc/thread-self/ns/net') != os.stat('/proc/1/ns/net'), 'refusing the host network namespace'
    if args.installed:
        assert os.stat('/proc/thread-self/ns/mnt') != os.stat('/proc/1/ns/mnt'), 'installed-entry probe requires a private mount namespace'
    helper = args.helper.resolve(strict=True)

    def ip(*arguments):
        return subprocess.check_output(['ip', *arguments], text=True, timeout=10)

    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'helperorig0', 'type', 'dummy')
    ip('link', 'set', 'helperorig0', 'up')
    ip('address', 'add', '192.0.2.1/24', 'dev', 'helperorig0')
    for name in ('all', 'default'):
        Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').write_text('1')

    def inventory():
        return (ip('-N', '-j', '-4', 'route', 'show', 'table', 'all'),
                ip('-N', '-j', '-4', 'rule', 'show'), socket.if_nameindex())

    baseline = inventory()
    control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    child = os.fork()
    if child == 0:
        control.close()
        try:
            user_agent(child_control, args.uid)
        except BaseException:
            os._exit(1)
        else:
            os._exit(0)
    child_control.close()
    control.settimeout(20)
    processes = []

    def command(operation, **values):
        control.sendall(encode({'operation': operation, **values}))
        result = json.loads(control.recv(65536))
        assert 'error' not in result, result
        return result

    def request(owner, operation):
        return {'version': 2, 'owner': owner, 'operation': operation}

    def application(owner):
        return {**request(owner, 'apply'), 'device': {'source': '198.18.0.1', 'peer': '198.18.0.2', 'mtu': 1400},
                'capture': ['198.18.4.0/24'],
                'underlay': {'interface': 'helperorig0', 'source': '192.0.2.1', 'gateway': '', 'prefixes': ['198.18.4.0/24']}}

    try:
        with tempfile.TemporaryDirectory(prefix='JustConnect-helper-test-') as temporary:
            os.chmod(temporary, 0o700)
            if args.installed:
                temporary = json.loads((Path(__file__).resolve().parents[2] / 'resource/network-helper.json').read_text())['state_directory']
                directory = None
            else:
                directory = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

            def start(owner, pid=None):
                command('listen', owner=owner)
                if args.installed:
                    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8', 'PKEXEC_UID': str(args.uid)}
                    process = subprocess.Popen([str(helper), owner, str(pid or child)], env=environment)
                else:
                    process = subprocess.Popen([str(helper), '--isolated', str(directory), str(args.uid), str(pid or child), owner], pass_fds=(directory,))
                processes.append(process)
                command('accept', pid=process.pid)
                return process

            def receive(owner, state, descriptor=0, success=True):
                value = command('receive')
                packet = value['packet']
                assert packet and packet['version'] == 2 and packet['owner'] == owner and packet['state'] == state, value
                assert (packet['status'] == 0) == success and value['descriptors'] == descriptor, value
                if descriptor:
                    assert packet['device']['owner'] == owner and packet['device']['interface'].startswith('jc'), value
                return packet

            def finish(owner, process):
                command('send', packet=request(owner, 'acknowledge'))
                assert process.wait(timeout=10) == 0
                command('close-descriptors')
                assert inventory() == baseline, 'helper changed the original network inventory'
                assert not list(Path(temporary).iterdir()), 'acknowledged operation left private state'

            if args.uninstalled_helper:
                assert args.installed
                owner = str(uuid.uuid4())
                command('listen', owner=owner)
                process = subprocess.Popen([str(args.uninstalled_helper.resolve(strict=True)), owner, str(child)],
                                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8', 'PKEXEC_UID': str(args.uid)})
                processes.append(process)
                assert process.wait(timeout=3) == 1
                command('listener-empty')
                assert inventory() == baseline and not Path(temporary).exists()
                print('PASS: identical root-owned binary outside the fixed installation path rejected before IPC/storage', flush=True)

            # Normal helper owns native operations; the ordinary receiver exchanges real IP packets.
            owner = str(uuid.uuid4())
            process = start(owner)
            command('send', packet=application(owner))
            receive(owner, 'active', 1)
            command('exchange')
            command('send', packet=request(owner, 'restore'))
            receive(owner, 'restored')
            finish(owner, process)
            print('PASS: authenticated ordinary peer, real fd/UDP handoff, scoped source/capture rollback and cleanup', flush=True)

            # A caller-supplied PID does not replace SO_PEERCRED authority.
            owner = str(uuid.uuid4())
            process = start(owner, os.getpid())
            assert command('receive')['packet'] is None and process.wait(timeout=10) != 0
            assert inventory() == baseline and not list(Path(temporary).iterdir())

            for mutation in ('owner', 'version', 'extra', 'prefix', 'mtu', 'descriptor'):
                owner = str(uuid.uuid4())
                process = start(owner)
                packet = application(owner)
                if mutation == 'owner':
                    packet['owner'] = str(uuid.uuid4())
                elif mutation == 'version':
                    packet['version'] += 1
                elif mutation == 'extra':
                    packet['program'] = '/bin/sh'
                elif mutation == 'prefix':
                    packet['capture'] = ['0.0.0.0/0']
                elif mutation == 'mtu':
                    packet['device']['mtu'] = 1400.5
                command('send', packet=packet, descriptor=mutation == 'descriptor')
                assert command('receive')['packet'] is None and process.wait(timeout=10) != 0, mutation
                assert inventory() == baseline and not list(Path(temporary).iterdir()), mutation
            print('PASS: spoofed PID/owner, wrong version, command injection, unsafe prefix/MTU and incoming fd rejected before writes', flush=True)

            # Native capture failure after source routing/device creation rolls back the completed steps.
            ip('route', 'add', '198.18.5.0/24', 'dev', 'helperorig0', 'proto', 'static', 'metric', '7')
            before_failure = inventory()
            owner = str(uuid.uuid4())
            process = start(owner)
            packet = application(owner)
            packet['capture'] = ['198.18.5.0/24']
            command('send', packet=packet)
            receive(owner, 'restored', success=False)
            assert inventory() == before_failure, 'partial apply damaged the external route or leaked source/device state'
            ip('route', 'del', '198.18.5.0/24', 'dev', 'helperorig0', 'metric', '7')
            finish(owner, process)
            print('PASS: native partial apply restores its source/device state and preserves the conflicting external route', flush=True)

            # Application dies: the helper independently restores, retaining a durable receipt.
            owner = str(uuid.uuid4())
            process = start(owner)
            command('send', packet=application(owner))
            receive(owner, 'active', 1)
            command('disconnect')
            assert process.wait(timeout=10) == 2, 'EOF must retain a recovery receipt, not report acknowledged cleanup'
            command('close-descriptors')
            assert inventory() == baseline
            saved = {path: path.read_bytes() for path in Path(temporary).rglob('*.json')}
            assert any(json.loads(contents).get('version') == 1 for contents in saved.values()), 'wire upgrade changed stored recovery metadata'
            process = start(owner)
            command('send', packet=application(owner))
            assert command('receive')['packet'] is None and process.wait(timeout=10) != 0
            assert all(path.read_bytes() == contents for path, contents in saved.items()), 'repeated apply replaced recovery authority'
            process = start(owner)
            command('send', packet=request(owner, 'recover'))
            receive(owner, 'restored')
            finish(owner, process)
            print('PASS: control EOF restores without GUI and a fresh helper confirms the saved completion', flush=True)

            # Only the owned fixture helper is killed. Its consumer keeps the actual device alive.
            owner = str(uuid.uuid4())
            process = start(owner)
            command('send', packet=application(owner))
            receive(owner, 'active', 1)
            process.kill()
            assert process.wait(timeout=10) < 0
            assert inventory() != baseline
            before_cleanup = inventory()
            process = start(owner)
            command('send', packet=request(owner, 'cleanup'))
            assert command('receive')['packet'] is None and process.wait(timeout=10) != 0
            assert inventory() == before_cleanup, 'receipt cleanup performed native recovery on an active connection'
            process = start(owner)
            command('send', packet=request(owner, 'recover'))
            receive(owner, 'restored')
            finish(owner, process)
            print('PASS: fresh authenticated helper restores durable native ownership after owned helper SIGKILL', flush=True)

            # A lost restore acknowledgement must not turn absence into guessed success.
            owner = str(uuid.uuid4())
            process = start(owner)
            command('send', packet=application(owner))
            receive(owner, 'active', 1)
            command('send', packet=request(owner, 'restore'))
            receive(owner, 'restored')
            command('disconnect')
            assert process.wait(timeout=10) == 2
            command('close-descriptors')
            process = start(owner)
            command('send', packet=request(owner, 'cleanup'))
            receive(owner, 'cleaned')
            assert process.wait(timeout=10) == 0
            assert inventory() == baseline and not list(Path(temporary).iterdir())
            process = start(owner)
            command('send', packet=request(owner, 'cleanup'))
            receive(owner, 'cleaned')
            assert process.wait(timeout=10) == 0, 'receipt cleanup must be safely repeatable after a lost completion'

            # Crash boundary: receipt deletion was durable, but its empty parent was not yet removed.
            owner = str(uuid.uuid4())
            process = start(owner)
            command('send', packet=application(owner))
            receive(owner, 'active', 1)
            command('send', packet=request(owner, 'restore'))
            receive(owner, 'restored')
            command('disconnect')
            assert process.wait(timeout=10) == 2
            command('close-descriptors')
            receipt = Path(temporary) / f'{args.uid}-{owner}'
            assert json.loads((receipt / 'source.json').read_text())['phase'] == 'restored'
            (receipt / 'capture').rmdir()
            (receipt / 'underlay').rmdir()
            (receipt / 'source.json').unlink()
            receipt_fd = os.open(receipt, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(receipt_fd)
            finally:
                os.close(receipt_fd)
            assert not list(receipt.iterdir()) and inventory() == baseline
            foreign = receipt / 'foreign'
            foreign.write_bytes(b'preserve unknown contents')
            process = start(owner)
            command('send', packet=request(owner, 'cleanup'))
            assert command('receive')['packet'] is None and process.wait(timeout=10) != 0
            assert foreign.read_bytes() == b'preserve unknown contents' and inventory() == baseline
            foreign.unlink()
            process = start(owner)
            command('send', packet=request(owner, 'cleanup'))
            receive(owner, 'cleaned')
            assert process.wait(timeout=10) == 0 and not receipt.exists(), 'interrupted final receipt removal cannot be retried'
            print('PASS: interrupted final receipt removal retries its empty directory; unknown contents remain untouched', flush=True)
            owner = str(uuid.uuid4())
            process = start(owner)
            command('send', packet=request(owner, 'recover'))
            assert command('receive')['packet'] is None and process.wait(timeout=10) != 0
            assert inventory() == baseline and not list(Path(temporary).iterdir())
            if directory is not None:
                os.close(directory)
            print('PASS: lost acknowledgement cleanup is repeatable, active cleanup refused; absent/foreign recovery never claims success', flush=True)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        try:
            command('exit')
        finally:
            control.close()
            _, status = os.waitpid(child, 0)
            assert status == 0
            ip('link', 'del', 'helperorig0')


if __name__ == '__main__':
    main()
