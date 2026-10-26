"""Exercise the real signed XPC daemon on a disposable macOS runner; no desktop approval claim."""
import argparse
import array
import ctypes
import json
import ipaddress
import os
from pathlib import Path
import plistlib
import pwd
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from unix_device_probe import allocate_unix

ROOT = Path(__file__).resolve().parents[2]
LAYOUT = json.loads((ROOT / 'resource/network-helper-macos.json').read_text())
APP_ID = plistlib.loads((ROOT / 'resource/Info.plist').read_bytes())['CFBundleIdentifier']
SERVICE = APP_ID + LAYOUT['service_suffix']


def run(*args, check=True, **kwargs):
    result = subprocess.run(list(map(str, args)), check=False, capture_output=True, timeout=90, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: '
                           + result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
    return result


def ipv4_addresses(interface):
    return set(re.findall(r'\binet (\S+)', run('/sbin/ifconfig', interface).stdout.decode()))


def wait_for(predicate, message):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError(message)


def sign(bundle, identity, identifier):
    command = ['/usr/bin/codesign', '--force', '--options', 'runtime', '--sign', identity]
    run(*command, '--identifier', SERVICE, bundle / 'Contents/MacOS' / LAYOUT['executable'])
    run(*command, '--deep', '--preserve-metadata=entitlements,identifier', bundle)
    if identifier != APP_ID:
        run(*command, '--identifier', identifier, bundle)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', bundle)


def certificate(directory, name, keychains):
    configuration = directory / (name + '.cnf')
    configuration.write_text('[req]\ndistinguished_name=dn\nx509_extensions=extensions\nprompt=no\n'
                             f'[dn]\nCN={name}\n[extensions]\nbasicConstraints=critical,CA:FALSE\n'
                             'keyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n')
    private, certificate = directory / (name + '.key'), directory / (name + '.pem')
    run('/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-config', configuration, '-keyout', private, '-out', certificate)
    archive, keychain = directory / (name + '.p12'), directory / (name + '.keychain-db')
    password = uuid.uuid4().hex
    run('/usr/bin/openssl', 'pkcs12', '-export', '-inkey', private, '-in', certificate,
        '-out', archive, '-passout', 'pass:' + password)
    run('/usr/bin/security', 'create-keychain', '-p', password, keychain)
    keychains.append(keychain)
    run('/usr/bin/security', 'unlock-keychain', '-p', password, keychain)
    run('/usr/bin/security', 'import', archive, '-k', keychain, '-P', password, '-T', '/usr/bin/codesign')
    run('/usr/bin/security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, keychain)
    digest = run('/usr/bin/openssl', 'x509', '-in', certificate, '-noout', '-fingerprint', '-sha1').stdout.decode().strip().split('=')[1].replace(':', '')
    # codesign resolves identities through the user's search list, as in the package signing job.
    current = shlex.split(run('/usr/bin/security', 'list-keychains', '-d', 'user').stdout.decode())
    run('/usr/bin/security', 'list-keychains', '-d', 'user', '-s', *current, keychain)
    identities = run('/usr/bin/security', 'find-identity', '-p', 'codesigning', keychain).stdout.decode()
    assert digest in identities, 'Temporary certificate has no matching signing key: ' + identities
    return digest


class Authorization:
    class Item(ctypes.Structure):
        _fields_ = [('name', ctypes.c_char_p), ('length', ctypes.c_size_t), ('value', ctypes.c_void_p), ('flags', ctypes.c_uint32)]

    def __init__(self):
        class Rights(ctypes.Structure):
            _fields_ = [('count', ctypes.c_uint32), ('items', ctypes.POINTER(Authorization.Item))]
        self.security = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
        self.reference = ctypes.c_void_p()
        self.security.AuthorizationCreate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
        self.security.AuthorizationCopyRights.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        self.security.AuthorizationMakeExternalForm.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.security.AuthorizationCreateFromExternalForm.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.security.AuthorizationFree.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        assert self.security.AuthorizationCreate(None, None, 0, ctypes.byref(self.reference)) == 0
        self.item = self.Item(LAYOUT['authorization_right'].encode(), 0, None, 0)
        self.rights = Rights(1, ctypes.pointer(self.item))
        # Root obtains the real existing system right without an interactive prompt.
        assert self.security.AuthorizationCopyRights(self.reference, ctypes.byref(self.rights), None, (1 << 1) | (1 << 4), None) == 0
        self.external = ctypes.create_string_buffer(32)  # Security.framework AuthorizationExternalForm ABI.
        assert self.security.AuthorizationMakeExternalForm(self.reference, self.external) == 0

    def close(self, *, destroy=True):
        if self.reference:
            self.security.AuthorizationFree(self.reference, (1 << 3) if destroy else 0)
            self.reference = ctypes.c_void_p()

    def can_import(self):
        reference = ctypes.c_void_p()
        if self.security.AuthorizationCreateFromExternalForm(self.external, ctypes.byref(reference)) != 0:
            return False
        self.security.AuthorizationFree(reference, 0)
        return True


def main(args):
    assert sys.platform == 'darwin' and os.geteuid() == 0 and args.uid > 0
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS'
    assert run('/bin/launchctl', 'print', 'system/' + SERVICE, check=False).returncode != 0, 'Refusing an installed service'
    account = pwd.getpwuid(args.uid)
    boot = run('/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid').stdout.decode().strip().lower()
    user_state = Path(LAYOUT['state_directory']) / boot / str(args.uid)
    assert not user_state.exists(), 'Refusing pre-existing ownership evidence'
    before = set(run('/sbin/ifconfig', '-l').stdout.decode().split())
    dns_before = json.loads(run(args.dns_probe, '--snapshot').stdout)
    output = Path(args.output).resolve(); output.mkdir(parents=True, exist_ok=True)
    policies = {}
    for right in (LAYOUT['authorization_right'], 'system.preferences.network'):
        policy = plistlib.loads(run('/usr/bin/security', 'authorizationdb', 'read', right).stdout)
        policies[right] = {key: value for key, value in policy.items()
            if key in ('class', 'rule', 'group', 'shared', 'authenticate-user', 'allow-root', 'timeout')}
    (output / 'authorization-policy.out').write_text(json.dumps(policies, indent=2) + '\n')
    print('CHECK: actual network authorization policy', json.dumps(policies), flush=True)
    processes, keychains, grants = [], [], []
    original_keychains = shlex.split(run('/usr/bin/security', 'list-keychains', '-d', 'user').stdout.decode())
    with tempfile.TemporaryDirectory(prefix='JustConnect-helper-', dir='/Library/Application Support') as temporary:
        bootstrapped = False
        try:
            directory = Path(temporary); directory.chmod(0o755)
            private = directory / 'signing'; private.mkdir(mode=0o700)
            bundle = directory / 'JustConnect.app'; binaries = bundle / 'Contents/MacOS'; binaries.mkdir(parents=True)
            shutil.copy2(args.client, binaries / 'JustConnect')
            shutil.copy2(args.helper, binaries / LAYOUT['executable'])
            (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': APP_ID, 'CFBundleExecutable': 'JustConnect',
                'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'CFBundleShortVersionString': '1', 'LSMinimumSystemVersion': '14.4'}))
            run(args.deploy_tool, bundle, '-executable=' + str(binaries / LAYOUT['executable']))
            identity = certificate(private, 'JustConnect disposable signing fixture', keychains)
            sign(bundle, identity, APP_ID)
            facts = json.loads(run(binaries / LAYOUT['executable'], '--version').stdout)
            assert facts['identity_ready'] and facts['protocol'] == LAYOUT['protocol'] and facts['revision'] == args.revision
            launch = plistlib.loads(Path(args.plist).read_bytes())
            assert launch['Label'] == SERVICE and launch['MachServices'] == {SERVICE: True} and launch['UserName'] == 'root'
            assert launch.pop('BundleProgram') == 'Contents/MacOS/' + LAYOUT['executable']
            launch['Program'] = str(binaries / LAYOUT['executable'])
            launch['StandardOutPath'], launch['StandardErrorPath'] = str(output / 'daemon.out'), str(output / 'daemon.err')
            launch_path = directory / (SERVICE + '.plist'); launch_path.write_bytes(plistlib.dumps(launch)); launch_path.chmod(0o644)

            def start(mode, *, app=bundle, owner=None, grant=False, target=account, control=None):
                def ordinary():
                    os.setgroups([]); os.setgid(target.pw_gid); os.setuid(target.pw_uid)
                read_fd, write_fd = os.pipe()
                if grant:
                    authorization = Authorization(); grants.append(authorization); os.write(write_fd, authorization.external.raw)
                os.close(write_fd)
                command = [str(app / 'Contents/MacOS/JustConnect'), mode]
                inherited = [read_fd]
                if not mode.startswith('--wire-'):
                    command += [str(read_fd)] + ([str(control.fileno())] if control else [owner] if owner else [])
                    if control:
                        inherited.append(control.fileno())
                elif owner:
                    command.append(owner)
                error_path = output / ('client-' + str(len(processes)) + '.err')
                error = error_path.open('wb')
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error,
                    preexec_fn=ordinary, pass_fds=inherited, cwd='/', env={'HOME': target.pw_dir, 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
                process.fixture_stderr = error_path
                error.close(); os.close(read_fd); processes.append(process); return process

            def event(process, expected):
                ready = select.select([process.stdout], [], [], 40)[0]
                if not ready:
                    service = run('/bin/launchctl', 'print', 'system/' + SERVICE, check=False).stdout.decode()
                    print('CHECK: managed helper', re.findall(r'^\s*(?:state|pid|last exit code|last terminating signal) =.*$', service, re.M), flush=True)
                    for path in user_state.glob('*/source.json'):
                        print('CHECK: owned recovery receipt', path.read_text(), flush=True)
                assert ready, 'Client event timed out: ' + expected
                value = process.stdout.readline()
                assert value, f'Client exited before {expected}: {process.poll()}\n' + process.fixture_stderr.read_text()
                value = json.loads(value)
                assert value['event'] == expected, value
                print('CHECK:', value, flush=True); return value

            def receipt(owner, phase):
                path = user_state / owner / 'source.json'
                try:
                    return json.loads(path.read_text())['phase'] == phase
                except (FileNotFoundError, json.JSONDecodeError):
                    return False

            def finish(process):
                status = process.wait(timeout=20)
                assert status == 0, f'Native client {process.pid} exited {status}'

            def helper_pid():
                service = run('/bin/launchctl', 'print', 'system/' + SERVICE).stdout.decode()
                pid = re.search(r'^\s*pid = (\d+)\s*$', service, re.M); assert pid
                return int(pid[1])

            def kill_helper():
                pid = helper_pid()
                print('CHECK: kill managed helper pid', pid, flush=True)
                os.kill(pid, signal.SIGKILL)

            def withdrawn(interface):
                for address in ('198.18.0.6', '198.18.0.7'):
                    result = run('/sbin/route', '-n', 'get', '-inet', address, check=False)
                    if re.search(r'^\s*interface:\s*' + re.escape(interface) + r'\s*$', result.stdout.decode(), re.M):
                        return False
                return True

            def published(owner, address="198.18.0.7"):
                try:
                    record = json.loads((user_state / owner / 'capture/source.json').read_text())
                    return any(ipaddress.IPv4Address(address) in ipaddress.IPv4Network(row['prefix']) and row['applied']
                               and not row['delete_started'] for row in record['routes'])
                except (FileNotFoundError, json.JSONDecodeError):
                    return False

            def publish(client, active):
                client.stdin.write(b'publish\n'); client.stdin.flush(); event(client, 'published')
                assert published(active['owner']), 'CoreEngine acknowledged before durable native DNS capture'

            def dns_restored():
                return json.loads(run(args.dns_probe, '--snapshot').stdout) == dns_before

            run('/bin/launchctl', 'bootstrap', 'system', launch_path)
            bootstrapped = True
            wait_for(lambda: user_state.parent.exists(), 'Signed root daemon did not start')
            for mode in ('--wire-denied', '--wire-invalid-auth', '--wire-ungranted-auth'):
                target = pwd.getpwnam('nobody') if mode == '--wire-ungranted-auth' else account
                denied = start(mode, target=target); event(denied, 'wire-denied'); finish(denied)
            assert not user_state.exists(), 'Authorization denial created ownership or network state'
            for name, wrong_identity in [('wrong-id', False), ('wrong-certificate', True)]:
                copy = directory / (name + '.app'); shutil.copytree(bundle, copy, symlinks=True)
                if wrong_identity:
                    other = certificate(private, 'JustConnect foreign signing fixture', keychains)
                    sign(copy, other, APP_ID)
                else:
                    sign(copy, identity, APP_ID + '.foreign')
                denied = start('--wire-untrusted', app=copy); event(denied, 'wire-denied'); finish(denied)
                assert not user_state.exists(), 'Untrusted signed executable created ownership storage'
            client = start('--publish', grant=True); active = event(client, 'active')
            assert receipt(active['owner'], 'active')
            for mode, target in [('--wire-live', account), ('--wire-live-extend', account), ('--wire-live-routes', account),
                                 ('--wire-foreign', pwd.getpwnam('nobody')), ('--wire-live-extend', pwd.getpwnam('nobody')), ('--wire-live-routes', pwd.getpwnam('nobody'))]:
                denied = start(mode, owner=active['owner'], target=target); event(denied, 'wire-denied'); finish(denied)
                assert receipt(active['owner'], 'active') and not withdrawn(active['interface']), 'Foreign connection withdrew live ownership'
            publish(client, active)
            checkpoint = user_state / active['owner'] / 'capture/source.json'
            unchanged = checkpoint.read_bytes()
            publish(client, active)
            assert checkpoint.read_bytes() == unchanged, 'Repeated DNS publication rewrote its confirmed record'
            client.stdin.write(b'restore\n'); client.stdin.flush(); event(client, 'restored'); finish(client)
            assert not (user_state / active['owner']).exists(), 'Confirmed restoration left an unacknowledged receipt'
            wait_for(dns_restored, 'Normal restore left owned DNS settings')
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            descriptors = array.array('i')
            try:
                client = start('--dns', grant=True, control=child); child.close(); active = event(client, 'active')
                assert select.select([parent], [], [], 5)[0], 'No ordinary DNS device handoff'
                token, ancillary, flags, _ = parent.recvmsg(1, socket.CMSG_SPACE(descriptors.itemsize))
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        descriptors.frombytes(data[:len(data) - len(data) % descriptors.itemsize])
                assert token == b'D' and not flags & socket.MSG_CTRUNC and len(descriptors) == 1
                device = descriptors[0]; os.set_inheritable(device, False)
                domain = active['dns_domains'][0]
                wait_for(lambda: domain in run('/usr/sbin/scutil', '--dns').stdout.decode(), 'Owned resolver did not become effective')
                lookup = run(sys.executable, ROOT / 'tests/platform/tundns_fixture.py', '--device', device,
                    '--hostname', 'host-' + uuid.uuid4().hex + '.' + domain, '--peer', active['peer'],
                    user=args.uid, group=account.pw_gid, extra_groups=(), pass_fds=(device,),
                    env={'HOME': account.pw_dir, 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'PYTHONDONTWRITEBYTECODE': '1'})
                print(lookup.stdout.decode(), end='', flush=True)
                client.stdin.write(b'restore\n'); client.stdin.flush(); event(client, 'restored'); finish(client)
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)
                parent.close(); child.close()
            wait_for(dns_restored, 'System resolver query fixture left DNS settings')
            cancelled = str(uuid.uuid4())
            client = start('--cancel', grant=True, owner=cancelled); event(client, 'applying')
            wait_for(lambda: receipt(cancelled, 'active'), 'Cancellation did not reach real privileged apply')
            client.stdin.write(b'cancel\n'); client.stdin.flush(); event(client, 'restored'); finish(client)
            assert not list(user_state.iterdir()), 'Cancelled apply leaked ownership'
            wait_for(dns_restored, 'Cancelled apply left owned DNS settings')
            client = start('--cancel-extend', grant=True); active = event(client, 'active')
            client.stdin.write(b'publish\n'); client.stdin.flush(); event(client, 'extending')
            wait_for(lambda: published(active['owner']), 'Cancellation did not reach durable native DNS publication')
            client.stdin.write(b'cancel\n'); client.stdin.flush(); event(client, 'restored'); finish(client)
            assert withdrawn(active['interface']) and not list(user_state.iterdir()), 'Cancelled DNS publication leaked capture ownership'
            wait_for(dns_restored, 'Cancelled DNS publication left resolver state')
            client = start('--publish', grant=True); active = event(client, 'active'); publish(client, active)
            client.kill(); client.wait(timeout=10)
            wait_for(lambda: receipt(active['owner'], 'restored') and withdrawn(active['interface']), 'Client EOF failed to restore owned capture')
            wait_for(dns_restored, 'Client EOF failed to restore owned DNS')
            recovery = start('--recover', owner=active['owner']); event(recovery, 'restored'); finish(recovery)
            client = start('--publish', grant=True); active = event(client, 'active'); publish(client, active)
            kill_helper(); event(client, 'lost')
            wait_for(dns_restored, 'Killed helper session left owned DNS settings')
            wait_for(lambda: receipt(active['owner'], 'restored') and withdrawn(active['interface']), 'New daemon did not restore capture while ordinary fd remained open')
            client.stdin.write(b'exit\n'); client.stdin.flush(); finish(client)
            recovery = start('--recover', owner=active['owner']); event(recovery, 'restored'); finish(recovery)
            assert not list(user_state.iterdir()), 'Recovered ownership was not acknowledged'
            core_bundle = directory / 'CoreConnect.app'
            shutil.copytree(bundle, core_bundle, symlinks=True)
            shutil.copy2(args.core_client, core_bundle / 'Contents/MacOS/JustConnect')
            sign(core_bundle, identity, APP_ID)
            crashed_owner = None
            for scenario in ('authorization-cancel', 'authorization-exit', 'process-crash', 'normal', 'network-policy', 'network-exit', 'helper-loss', 'helper-offline'):
                control = directory / ('core-' + scenario); control.mkdir(mode=0o700); os.chown(control, args.uid, account.pw_gid)
                marker = control / 'ready'
                authorization_mode = scenario.removeprefix('authorization-') if scenario.startswith('authorization-') else ''
                authorization_count = 3 if authorization_mode == 'cancel' else 1 if authorization_mode == 'exit' or scenario == 'process-crash' else 2
                authorizations = [Authorization() for _ in range(authorization_count)]; grants.extend(authorizations)
                read_fd, write_fd = os.pipe()
                original_fd = -1
                external_alias = None
                transcript = output / ('core-' + scenario + '.out')
                try:
                    os.write(write_fd, b''.join(value.external.raw for value in authorizations)); os.close(write_fd); write_fd = -1
                    environment = {'HOME': account.pw_dir, 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'macOS',
                        'JC_NATIVE_TUN_HOST': str(core_bundle / 'Contents/MacOS/JustConnect'),
                        'JC_NATIVE_TUN_MAC_AUTH_FD': str(read_fd), 'JC_NATIVE_TUN_DNS': '1'}
                    if authorization_mode:
                        environment.update(JC_NATIVE_NETWORK_AUTHORIZATION=authorization_mode, JC_NATIVE_TUN_READY=str(marker))
                    elif scenario == 'network-exit':
                        environment.update(JC_NATIVE_NETWORK_EXIT_CHANGE='1', JC_NATIVE_TUN_READY=str(marker))
                    elif scenario == 'network-policy':
                        original_fd, original_interface, release_allocator = allocate_unix(Path(args.allocator).resolve())
                        release_allocator()
                        os.set_blocking(original_fd, False)
                        environment.update(JC_NATIVE_NETWORK_POLICY='1', JC_NATIVE_TUN_READY=str(marker), JC_NATIVE_ORIGINAL_FD=str(original_fd))
                    elif scenario != 'normal':
                        environment.update(JC_NATIVE_NETWORK_HELPER_LOSS='1', JC_NATIVE_TUN_READY=str(marker),
                            JC_NATIVE_NETWORK_HELPER_OFFLINE='1' if scenario == 'helper-offline' else '0')
                    elif crashed_owner:
                        assert receipt(crashed_owner, 'restored'), 'Restart must encounter the unacknowledged crash receipt'
                        environment['JC_NATIVE_TUN_READY'] = str(marker)
                    test_name = 'TestNativeTUNAuthorizationExit' if authorization_mode == 'exit' else 'TestNativeTUNProcessCrash' if scenario == 'process-crash' else 'TestNativeTUNHost'
                    with transcript.open('wb') as stream:
                        core = subprocess.Popen([args.gateway, '-test.v', '-test.timeout', '75s', '-test.run', '^' + test_name + '$'],
                            user=args.uid, group=account.pw_gid, extra_groups=(), pass_fds=(read_fd,) + ((original_fd,) if original_fd >= 0 else ()), env=environment,
                            stdout=stream, stderr=subprocess.STDOUT)
                    processes.append(core)

                    def boundary(suffix):
                        def reached():
                            assert core.poll() is None, 'Qt/core exited before ' + suffix + ': ' + transcript.read_text()
                            return Path(str(marker) + suffix).exists()
                        wait_for(reached, 'Qt/core did not reach ' + scenario + suffix)

                    def active_owner():
                        owners = list(user_state.glob('*/source.json')); assert len(owners) == 1, owners
                        value = json.loads(owners[0].read_text()); assert value['phase'] == 'active', value
                        return value

                    if authorization_mode:
                        boundary('.authorizing')
                        assert not list(user_state.iterdir()) and dns_restored(), 'Pending authorization changed native network ownership'
                        if authorization_mode == 'cancel':
                            authorizations[0].close(destroy=False)
                            assert authorizations[0].can_import(), 'Blocked provider must retain the actual old authorization reference'
                        Path(str(marker) + '.cancel').touch()
                        if authorization_mode == 'cancel':
                            boundary('.cancelled'); boundary('.current-authorizing')
                            assert not list(user_state.iterdir()), 'Cancelled authorization retained a privileged operation'
                            Path(str(marker) + '.release-old').touch(); boundary('.old-returned')
                            wait_for(lambda: not authorizations[0].can_import(), 'Late cancelled authorization reference was not released')
                            assert all(grant.can_import() for grant in authorizations[1:]), 'Late authorization cleanup destroyed the new authorization contexts'
                            assert not list(user_state.iterdir()) and dns_restored(), 'Old authorization approved the new pending connection'
                            Path(str(marker) + '.approve').touch()
                            print('CHECK: cancelled authorization revoked before current authorization was approved', flush=True)
                    elif scenario == 'network-exit':
                        boundary('.exit-ready'); active = active_owner()
                        snapshot = json.loads(Path(str(marker) + '.exit-ready').read_text())
                        defaults = {row['interface_index'] for row in snapshot['network']['routes'] if row['destination'] == '0.0.0.0/0'}
                        interfaces = [row for row in snapshot['network']['interfaces'] if row['index'] in defaults and row['up'] and not row['loopback']]
                        assert len(interfaces) == 1, 'Exit change fixture requires one actual IPv4 default interface'
                        interface = interfaces[0]['name']
                        assigned = ipv4_addresses('-a')
                        address = next(str(value) for value in ipaddress.ip_network('192.0.2.0/24').hosts() if str(value) not in assigned)
                        before_addresses = ipv4_addresses(interface)
                        external_alias = (interface, address, before_addresses)
                        run('/sbin/ifconfig', interface, 'inet', address, 'netmask', '255.255.255.255', 'alias')
                        assert ipv4_addresses(interface) == before_addresses | {address}, 'Address alias altered an existing original address'
                        boundary('.exit-restored')
                        assert not list(user_state.iterdir()), 'Exit change scheduled a new core before restoring the old owner'
                        wait_for(dns_restored, 'Exit change left the old owned DNS installed')
                        wait_for(lambda: active['device']['interface'] not in run('/sbin/ifconfig', '-l').stdout.decode().split(),
                            'Exit change retained the old core/device reference')
                        Path(str(marker) + '.continue').touch(); boundary('.exit-reconnected')
                        fresh = active_owner()
                        assert fresh['owner'] != active['owner'], 'Exit change reused the old privileged owner'
                        changed = json.loads(Path(str(marker) + '.exit-reconnected').read_text())
                        assert changed['generation'] != snapshot['generation'], 'Exit change reused the old core generation'
                        assert any(row['index'] == interfaces[0]['index'] and address + '/32' in row['addresses']
                                   for row in changed['network']['interfaces']), 'Fresh connection did not adopt the actual changed exit address'
                        assert ipv4_addresses(interface) == before_addresses | {address}, 'Recovery altered the external original address inventory'
                        Path(str(marker) + '.traffic').touch()
                        print('CHECK: actual exit address change restored', active['owner'], 'before fresh owner', fresh['owner'], flush=True)
                    elif scenario == 'network-policy':
                        boundary('.policy-ready'); active = active_owner()
                        assert published(active['owner']), 'Overlap test preceded confirmed dynamic DNS capture'
                        external = ('-n', 'add', '-inet', '-net', '198.18.0.0/29', '-interface', original_interface, '-static')
                        run('/sbin/route', *external)
                        try:
                            Path(str(marker) + '.overlay-up').touch(); boundary('.protected')
                            assert not any(published(active['owner'], address) for address in ('198.18.0.6', '198.18.0.7')), 'New original protection retained campus capture'
                            Path(str(marker) + '.select-campus').touch(); boundary('.campus-selected')
                            assert published(active['owner']) and active_owner()['owner'] == active['owner'], 'Explicit campus choice lost its active ownership'
                            Path(str(marker) + '.select-original').touch(); boundary('.original-selected')
                            assert not any(published(active['owner'], address) for address in ('198.18.0.6', '198.18.0.7')), 'Original-side choice retained a campus host route'
                            original = run('/sbin/route', '-n', 'get', '-inet', '198.18.0.3').stdout.decode()
                            assert re.search(r'^\s*interface:\s*' + re.escape(original_interface) + r'\s*$', original, re.M), 'Policy update removed the external original route'
                        finally:
                            run('/sbin/route', '-n', 'delete', '-inet', '-net', '198.18.0.0/29', '-interface', original_interface)
                        Path(str(marker) + '.overlay-down').touch(); boundary('.policy-restored')
                        assert all(published(active['owner'], address) for address in ('198.18.0.6', '198.18.0.7')), 'Overlay removal lost the still-live DNS binding or campus IP resource'
                        Path(str(marker) + '.traffic').touch()
                        print('CHECK: live overlap protected, explicitly selected, withdrawn and restored within owner', active['owner'], flush=True)
                    elif scenario == 'process-crash':
                        boundary(''); active = active_owner()
                        assert published(active['owner']), 'Full-process crash preceded actual DNS and data traffic'
                        pid = int(json.loads(marker.read_text())['pid'])
                        parent, uid = map(int, run('/bin/ps', '-p', pid, '-o', 'ppid=', '-o', 'uid=').stdout.split())
                        assert (parent, uid) == (core.pid, args.uid), 'Refusing an unrelated native process'
                        daemon = helper_pid()
                        os.kill(daemon, signal.SIGSTOP)
                        try:
                            os.kill(pid, signal.SIGKILL)
                        finally:
                            os.kill(daemon, signal.SIGKILL)
                        crashed_owner = active['owner']
                        wait_for(lambda: receipt(crashed_owner, 'restored'), 'Independent daemon did not recover after full Qt/core and helper kill')
                        wait_for(lambda: active['device']['interface'] not in run('/sbin/ifconfig', '-l').stdout.decode().split(),
                            'Full-process crash retained the owned utun')
                        wait_for(dns_restored, 'Full-process crash left owned DNS settings')
                        print('CHECK: full Qt/core and helper killed; independent recovery retained receipt', crashed_owner, flush=True)
                    elif scenario == 'normal' and crashed_owner:
                        boundary('.reconnected'); fresh = active_owner()
                        assert fresh['owner'] != crashed_owner and not (user_state / crashed_owner).exists(), 'New application did not acknowledge old crash recovery before acquiring fresh ownership'
                        Path(str(marker) + '.traffic').touch()
                        print('CHECK: new application acknowledged crash recovery before fresh owner', fresh['owner'], flush=True)
                        crashed_owner = None
                    elif scenario != 'normal':
                        boundary(''); active = active_owner()
                        assert published(active['owner']), 'Fault preceded actual DNS publication and data traffic'
                        if scenario == 'helper-offline':
                            run('/bin/launchctl', 'bootout', 'system/' + SERVICE); bootstrapped = False
                            boundary('.blocked')
                            assert (user_state / active['owner'] / 'source.json').exists(), 'Offline restoration lost its ownership receipt'
                            wait_for(lambda: active['device']['interface'] not in run('/sbin/ifconfig', '-l').stdout.decode().split(),
                                'Stopped core retained an owned utun while its helper was unavailable')
                            wait_for(dns_restored, 'Offline helper session left owned DNS settings')
                            run('/bin/launchctl', 'bootstrap', 'system', launch_path); bootstrapped = True
                            wait_for(lambda: receipt(active['owner'], 'restored'), 'Reloaded daemon did not recover the old owner')
                        else:
                            kill_helper(); boundary('.released')
                            wait_for(lambda: not (user_state / active['owner']).exists() or receipt(active['owner'], 'restored'),
                                'Reloaded helper did not restore the failed full core session')
                        Path(str(marker) + '.continue').touch()
                        boundary('.restored')
                        assert not list(user_state.iterdir()), 'Full core failure acknowledged restoration before receipt cleanup'
                        wait_for(lambda: active['device']['interface'] not in run('/sbin/ifconfig', '-l').stdout.decode().split(),
                            'Completed helper loss retained a core/device reference')
                        wait_for(dns_restored, 'Full Qt/core helper loss left owned DNS settings')
                        Path(str(marker) + '.restart').touch(); boundary('.reconnected')
                        fresh = active_owner()
                        assert fresh['owner'] != active['owner'], 'Restart reused the failed privileged ownership'
                        Path(str(marker) + '.traffic').touch()
                        print('CHECK: full Qt/core', scenario, active['owner'], 'restored before fresh owner', fresh['owner'], flush=True)
                    try:
                        finish(core)
                    finally:
                        print(transcript.read_text(), end='', flush=True)
                finally:
                    if external_alias:
                        interface, address, before_addresses = external_alias
                        if address in ipv4_addresses(interface):
                            run('/sbin/ifconfig', interface, 'inet', address, '-alias')
                        assert ipv4_addresses(interface) == before_addresses, 'Exit change fixture altered the original address inventory'
                    os.close(read_fd)
                    if original_fd >= 0:
                        os.close(original_fd)
                    if write_fd >= 0:
                        os.close(write_fd)
                if scenario != 'process-crash':
                    assert not list(user_state.iterdir()), 'Actual Qt/core session retained an ownership receipt'
                wait_for(dns_restored, 'Actual Qt/core session left original DNS changed')
            print('PASS: signed root XPC, identity/network authorization boundaries, ordinary UDP/fd and system DNS, durable CoreEngine DNS publication, cancellation, EOF and daemon restart recovery', flush=True)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=10)
            if bootstrapped:
                run('/bin/launchctl', 'bootout', 'system/' + SERVICE, check=False)
            for grant in grants:
                grant.close()
            run('/usr/bin/security', 'list-keychains', '-d', 'user', '-s', *original_keychains)
            for keychain in keychains:
                run('/usr/bin/security', 'delete-keychain', keychain, check=False)
    wait_for(lambda: set(run('/sbin/ifconfig', '-l').stdout.decode().split()) == before, 'Owned utun survived completed fixture')
    wait_for(lambda: json.loads(run(args.dns_probe, '--snapshot').stdout) == dns_before, 'Original DNS inventory changed after helper fixture')
    if user_state.exists():
        assert not list(user_state.iterdir()), 'Preserve unresolved ownership evidence'
        user_state.rmdir()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True)
    for name in ('helper', 'client', 'plist', 'deploy-tool', 'revision', 'output', 'dns-probe', 'core-client', 'gateway', 'allocator'):
        parser.add_argument('--' + name, required=True)
    main(parser.parse_args())
