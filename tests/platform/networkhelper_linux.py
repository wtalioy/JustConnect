"""Actual ordinary-user/helper IPC and durable recovery, inside a private netns only."""

import argparse
import array
import errno
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
from tundns_fixture import query_via_tun

LAYOUT = json.loads((Path(__file__).resolve().parents[2] / 'resource/network-helper.json').read_text())

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
                exchange(descriptors[0], command.get('target','198.18.4.7'))
            elif operation == 'query':
                assert len(descriptors) == 1
                query_via_tun(descriptors[0], command['name'], '198.18.0.2', uid,
                              {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'})
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
    parser.add_argument('--dns-probe', type=Path, help='actual resolved and restricted recovery fixture')
    args = parser.parse_args()
    assert os.geteuid() == 0 and args.uid != 0
    assert os.stat('/proc/thread-self/ns/net') != os.stat('/proc/1/ns/net'), 'refusing the host network namespace'
    if args.installed:
        assert os.stat('/proc/thread-self/ns/mnt') != os.stat('/proc/1/ns/mnt'), 'installed-entry probe requires a private mount namespace'
    helper = args.helper.resolve(strict=True)
    dns_probe = args.dns_probe.resolve(strict=True) if args.dns_probe else None

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
    def start_receiver():
        control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        child = os.fork()
        if child == 0:
            # A replacement ordinary caller must not inherit the root recovery directory or other capabilities.
            for value in os.listdir('/proc/self/fd'):
                fd = int(value)
                if fd >= 3 and fd != child_control.fileno():
                    try:
                        os.close(fd)
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise
            try:
                user_agent(child_control, args.uid)
            except BaseException:
                os._exit(1)
            else:
                os._exit(0)
        child_control.close()
        control.settimeout(20)
        return control, child

    control, child = start_receiver()
    processes = []

    def command(operation, **values):
        control.sendall(encode({'operation': operation, **values}))
        result = json.loads(control.recv(65536))
        assert 'error' not in result, result
        return result

    def request(owner, operation):
        return {'version': LAYOUT['protocol'], 'owner': owner, 'operation': operation}

    def application(owner):
        return {**request(owner, 'apply'), 'device': {'source': '198.18.0.1', 'peer': '198.18.0.2', 'mtu': 1400},
                'capture': ['198.18.4.0/24'], 'dns': ['campus.test'] if dns_probe else [],
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

            def scan(success=True):
                if args.installed:
                    arguments, inherited = [str(helper), '--recover-stale'], ()
                    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8'}
                else:
                    arguments, inherited = [str(helper), '--scan-isolated', str(directory)], (directory,)
                    environment = None
                    if dns_probe:
                        inherited += tuple(map(int, os.environ['JC_TEST_HOST_NAMESPACE_FDS'].split(',')))
                        arguments = ['/usr/bin/setpriv', '--bounding-set=-all,+net_admin', str(dns_probe), '--scan-isolated', str(directory)]
                result = subprocess.run(arguments, pass_fds=inherited, env=environment, text=True, capture_output=True, timeout=30)
                summary = json.loads(result.stdout)
                assert (result.returncode == 0) == success and summary['worker'] == 'network-recovery', (summary, result.stderr)
                return summary

            def receive(owner, state, descriptor=0, success=True):
                value = command('receive')
                packet = value['packet']
                assert packet and packet['version'] == LAYOUT['protocol'] and packet['owner'] == owner and packet['state'] == state, value
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
            held = inventory()
            saved_live = {path: path.read_bytes() for path in Path(temporary).rglob('*.json')}
            summary = scan()
            assert summary['checked'] == summary['live'] == 1 and summary['restored'] == summary['failed'] == 0
            assert inventory() == held and all(path.read_bytes() == contents for path, contents in saved_live.items())
            command('exchange')
            command('send',packet={**request(owner,'extend'),'addresses':['198.18.6.7']})
            receive(owner,'active')
            command('exchange',target='198.18.6.7')
            extended = inventory()
            command('send',packet={**request(owner,'extend'),'addresses':['198.18.6.7']})
            assert receive(owner,'active')['changed'] is False and inventory() == extended
            if dns_probe:
                command('query', name='helper-' + uuid.uuid4().hex + '.campus.test')
                print('PASS: ordinary system DNS query through authenticated helper-owned TUN fd', flush=True)
            command('send', packet=request(owner, 'restore'))
            receive(owner, 'restored')
            finish(owner, process)
            print('PASS: authenticated ordinary peer, real fd/UDP handoff, scoped source/capture rollback and cleanup', flush=True)

            owner = str(uuid.uuid4())
            process = start(owner)
            command('send',packet=application(owner))
            receive(owner,'active',1)
            command('send',packet={**request(owner,'extend'),'addresses':['198.18.6.7'],'program':'/bin/sh'})
            assert command('receive')['packet'] is None and process.wait(timeout=10) == 2
            command('close-descriptors')
            assert inventory() == baseline
            process = start(owner)
            command('send',packet=request(owner,'recover'))
            receive(owner,'restored')
            finish(owner,process)
            print('PASS: malformed active DNS publication restores only its owner and retains an acknowledged recovery path',flush=True)

            # A write-ahead host hint can survive before any privileged operation exists.
            owner = str(uuid.uuid4())
            for _ in range(2):
                process = start(owner)
                command('send', packet=request(owner, 'recover'))
                receive(owner, 'cleaned')
                assert process.wait(timeout=10) == 0
                assert inventory() == baseline and not list(Path(temporary).iterdir())
            print('PASS: absent recovery ownership is idempotent and never writes native state', flush=True)

            # A caller-supplied PID does not replace SO_PEERCRED authority.
            owner = str(uuid.uuid4())
            process = start(owner, os.getpid())
            assert command('receive')['packet'] is None and process.wait(timeout=10) != 0
            assert inventory() == baseline and not list(Path(temporary).iterdir())

            for mutation in ('owner', 'version', 'extra', 'prefix', 'mtu', 'descriptor', 'dns', 'missing-dns'):
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
                elif mutation == 'dns':
                    packet['dns'] = ['Campus.test']
                elif mutation == 'missing-dns':
                    del packet['dns']
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
            packet['capture'] = ['198.18.5.0/24', packet['device']['peer'] + '/32']
            command('send', packet=packet)
            receive(owner, 'restored', success=False)
            assert inventory() == before_failure, 'partial apply damaged the external route or leaked source/device state'
            ip('route', 'del', '198.18.5.0/24', 'dev', 'helperorig0', 'metric', '7')
            finish(owner, process)
            print('PASS: native partial apply restores its source/device state and preserves the original external route', flush=True)

            ip('route','add','198.18.6.7/32','dev','helperorig0','proto','static','metric','7')
            before_failure = inventory()
            owner = str(uuid.uuid4())
            process = start(owner)
            command('send',packet=application(owner))
            receive(owner,'active',1)
            command('send',packet={**request(owner,'extend'),'addresses':[application(owner)['device']['peer']]})
            receive(owner,'restored',success=False)
            command('close-descriptors')
            assert inventory() == before_failure,'failed DNS capture publication lost the foreign route or its source rollback'
            ip('route','del','198.18.6.7/32','dev','helperorig0','metric','7')
            finish(owner,process)
            print('PASS: DNS publication endpoint rejection reverses its source additions and preserves the external route',flush=True)

            # Application dies: the helper independently restores, retaining a durable receipt.
            owner = str(uuid.uuid4())
            process = start(owner)
            command('send', packet=application(owner))
            receive(owner, 'active', 1)
            command('send',packet={**request(owner,'extend'),'addresses':['198.18.6.7']})
            receive(owner,'active')
            command('disconnect')
            assert process.wait(timeout=10) == 2, 'EOF must retain a recovery receipt, not report acknowledged cleanup'
            command('close-descriptors')
            assert inventory() == baseline
            saved = {path: path.read_bytes() for path in Path(temporary).rglob('*.json')}
            assert json.loads((Path(temporary) / f'{args.uid}-{owner}' / 'source.json').read_bytes())['version'] == LAYOUT['storage_version']
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
            command('send',packet={**request(owner,'extend'),'addresses':['198.18.6.7']})
            receive(owner,'active')
            process.kill()
            assert process.wait(timeout=10) < 0
            assert inventory() != baseline
            before_cleanup = inventory()
            process = start(owner)
            command('send', packet=request(owner, 'cleanup'))
            assert command('receive')['packet'] is None and process.wait(timeout=10) != 0
            assert inventory() == before_cleanup, 'receipt cleanup performed native recovery on an active connection'
            context_file = Path(temporary) / f'{args.uid}-{owner}' / 'source.json'
            if dns_probe:
                dns_file = context_file.parent / 'dns/source.json'
                original_dns = dns_file.read_bytes()
                foreign_dns = json.loads(original_dns)
                foreign_dns['namespace'] += '.foreign'
                dns_file.write_bytes(encode(foreign_dns))
                summary = scan(success=False)
                assert summary['failed'] == 1 and summary['restored'] == 0 and inventory() == before_cleanup, \
                    'failed DNS recovery released capture or original egress prematurely'
                dns_file.write_bytes(original_dns)
            if not dns_probe:
                # A real active pre-DNS record has version1 and no DNS operation directory.
                (context_file.parent / 'dns').rmdir()
                legacy = json.loads(context_file.read_bytes())
                legacy['version'] = 1
                context_file.write_bytes(encode(legacy))
            original_context = context_file.read_bytes()
            foreign_context = json.loads(original_context)
            foreign_context['namespace'] += '.foreign'
            context_file.write_bytes(encode(foreign_context))
            summary = scan(success=False)
            assert summary['failed'] == 1 and summary['restored'] == 0 and inventory() == before_cleanup
            context_file.write_bytes(original_context)
            summary = scan()
            assert summary['restored'] == 1 and summary['failed'] == summary['live'] == 0
            summary = scan()
            assert summary['unchanged'] == 1 and summary['restored'] == 0
            outside = Path(temporary).parent / (Path(temporary).name + '-foreign')
            outside.mkdir(mode=0o700)
            sentinel = outside / 'preserve'
            sentinel.write_bytes(b'foreign private storage')
            alias = Path(temporary) / f'{args.uid}-{uuid.uuid4()}'
            alias.symlink_to(outside, target_is_directory=True)
            try:
                summary = scan(success=False)
                assert summary['failed'] == 1 and summary['unchanged'] == 1
                assert sentinel.read_bytes() == b'foreign private storage' and list(outside.iterdir()) == [sentinel]
            finally:
                alias.unlink()
                sentinel.unlink()
                outside.rmdir()
            process = start(owner)
            command('send', packet=request(owner, 'recover'))
            receive(owner, 'restored')
            finish(owner, process)
            print('PASS: fresh authenticated helper restores durable native ownership after owned helper SIGKILL', flush=True)

            # A lost acknowledgement retains its receipt until authenticated cleanup.
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
            empty_summary = scan()
            assert empty_summary['checked'] == 0 and not empty_summary['limited']
            excessive = [Path(temporary) / f'unknown-{index}' for index in range(empty_summary['capacity'] + 1)]
            try:
                for path in excessive:
                    path.touch(mode=0o600)
                summary = scan(success=False)
                assert summary['limited'] and summary['checked'] == summary['failed'] == empty_summary['capacity']
                assert all(path.is_file() and path.stat().st_size == 0 for path in excessive) and inventory() == baseline
            finally:
                for path in excessive:
                    path.unlink()
            print('PASS: system recovery bounds storage enumeration and preserves unknown entries', flush=True)
            process = start(owner)
            command('send', packet=request(owner, 'cleanup'))
            receive(owner, 'cleaned')
            assert process.wait(timeout=10) == 0, 'receipt cleanup must be safely repeatable after a lost completion'

            # Both original processes are gone: system recovery needs only trusted records, not a live GUI PID.
            owner = str(uuid.uuid4())
            process = start(owner)
            command('send', packet=application(owner))
            receive(owner, 'active', 1)
            process.kill()
            assert process.wait(timeout=10) < 0
            command('exit')
            control.close()
            _, status = os.waitpid(child, 0)
            child = -1
            assert status == 0 and inventory() != baseline
            summary = scan()
            assert summary['restored'] == 1 and summary['failed'] == summary['live'] == 0 and inventory() == baseline
            control, child = start_receiver()
            process = start(owner)
            command('send', packet=request(owner, 'recover'))
            receive(owner, 'restored')
            finish(owner, process)
            print('PASS: trusted system recovery skips live locks, rejects foreign namespace, and restores after GUI and helper both exit', flush=True)

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
            (receipt / 'dns').rmdir()
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
            with tempfile.TemporaryDirectory(prefix='JustConnect-foreign-recovery-') as outside:
                foreign = Path(outside) / 'preserve'
                foreign.write_bytes(b'foreign ownership is not absence')
                alias = Path(temporary) / f'{args.uid}-{owner}'
                alias.symlink_to(outside, target_is_directory=True)
                process = start(owner)
                command('send', packet=request(owner, 'recover'))
                assert command('receive')['packet'] is None and process.wait(timeout=10) != 0
                assert inventory() == baseline and foreign.read_bytes() == b'foreign ownership is not absence'
                assert list(Path(outside).iterdir()) == [foreign]
                alias.unlink()
            assert not list(Path(temporary).iterdir())
            if directory is not None:
                os.close(directory)
            print('PASS: lost acknowledgement cleanup is repeatable, active cleanup refused; foreign recovery never claims success; absent ownership is explicitly cleaned', flush=True)
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        try:
            if child > 0:
                try:
                    command('exit')
                finally:
                    control.close()
                    _, status = os.waitpid(child, 0)
                    assert status == 0
        finally:
            ip('link', 'del', 'helperorig0')


if __name__ == '__main__':
    main()
