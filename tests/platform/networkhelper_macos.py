"""Exercise the real signed XPC daemon on a disposable macOS runner; no desktop approval claim."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
LAYOUT = json.loads((ROOT / 'resource/network-helper-macos.json').read_text())
APP_ID = plistlib.loads((ROOT / 'resource/Info.plist').read_bytes())['CFBundleIdentifier']
SERVICE = APP_ID + LAYOUT['service_suffix']


def run(*args, check=True, **kwargs):
    return subprocess.run(list(map(str, args)), check=check, capture_output=True, timeout=90, **kwargs)


def wait_for(predicate, message):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError(message)


def sign(bundle, identity, keychain, identifier):
    command = ['/usr/bin/codesign', '--force', '--options', 'runtime', '--keychain', str(keychain), '--sign', identity]
    for framework in (bundle / 'Contents/Frameworks').glob('*.framework'):
        run(*command, '--deep', framework)
    run(*command, '--identifier', SERVICE, bundle / 'Contents/MacOS' / LAYOUT['executable'])
    run(*command, '--identifier', identifier, bundle)
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', bundle)


def certificate(directory, name):
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
    run('/usr/bin/security', 'unlock-keychain', '-p', password, keychain)
    run('/usr/bin/security', 'import', archive, '-k', keychain, '-P', password, '-T', '/usr/bin/codesign')
    run('/usr/bin/security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, keychain)
    digest = run('/usr/bin/openssl', 'x509', '-in', certificate, '-noout', '-fingerprint', '-sha1').stdout.decode().strip().split('=')[1].replace(':', '')
    return digest, keychain


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
        self.security.AuthorizationFree.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        assert self.security.AuthorizationCreate(None, None, 0, ctypes.byref(self.reference)) == 0
        item = self.Item(LAYOUT['authorization_right'].encode(), 0, None, 0)
        rights = Rights(1, ctypes.pointer(item))
        # Root obtains the real existing system right without an interactive prompt.
        assert self.security.AuthorizationCopyRights(self.reference, ctypes.byref(rights), None, (1 << 1) | (1 << 4), None) == 0
        self.external = ctypes.create_string_buffer(32)  # Security.framework AuthorizationExternalForm ABI.
        assert self.security.AuthorizationMakeExternalForm(self.reference, self.external) == 0

    def close(self):
        self.security.AuthorizationFree(self.reference, 1 << 3)


def main(args):
    assert sys.platform == 'darwin' and os.geteuid() == 0 and args.uid > 0
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'macOS'
    assert run('/bin/launchctl', 'print', 'system/' + SERVICE, check=False).returncode != 0, 'Refusing an installed service'
    account = pwd.getpwuid(args.uid)
    boot = run('/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid').stdout.decode().strip().lower()
    user_state = Path(LAYOUT['state_directory']) / boot / str(args.uid)
    assert not user_state.exists(), 'Refusing pre-existing ownership evidence'
    before = set(run('/sbin/ifconfig', '-l').stdout.decode().split())
    output = Path(args.output).resolve(); output.mkdir(parents=True, exist_ok=True)
    processes, keychains, grants = [], [], []
    with tempfile.TemporaryDirectory(prefix='JustConnect-helper-', dir='/Library/Application Support') as temporary:
        directory = Path(temporary); directory.chmod(0o755)
        private = directory / 'signing'; private.mkdir(mode=0o700)
        bundle = directory / 'JustConnect.app'; binaries = bundle / 'Contents/MacOS'; binaries.mkdir(parents=True)
        shutil.copy2(args.client, binaries / 'JustConnect')
        shutil.copy2(args.helper, binaries / LAYOUT['executable'])
        (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': APP_ID, 'CFBundleExecutable': 'JustConnect',
            'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'CFBundleShortVersionString': '1', 'LSMinimumSystemVersion': '14.4'}))
        run(args.deploy_tool, bundle, '-executable=' + str(binaries / LAYOUT['executable']))
        identity, keychain = certificate(private, 'JustConnect disposable signing fixture'); keychains.append(keychain)
        sign(bundle, identity, keychain, APP_ID)
        facts = json.loads(run(binaries / LAYOUT['executable'], '--version').stdout)
        assert facts['identity_ready'] and facts['protocol'] == LAYOUT['protocol'] and facts['revision'] == args.revision
        launch = plistlib.loads(Path(args.plist).read_bytes())
        assert launch['Label'] == SERVICE and launch['MachServices'] == {SERVICE: True} and launch['UserName'] == 'root'
        assert launch.pop('BundleProgram') == 'Contents/MacOS/' + LAYOUT['executable']
        launch['Program'] = str(binaries / LAYOUT['executable'])
        launch['StandardOutPath'], launch['StandardErrorPath'] = str(output / 'daemon.out'), str(output / 'daemon.err')
        launch_path = directory / (SERVICE + '.plist'); launch_path.write_bytes(plistlib.dumps(launch)); launch_path.chmod(0o644)

        def start(mode, *, app=bundle, owner=None, grant=False, target=account):
            def ordinary():
                os.setgroups([]); os.setgid(target.pw_gid); os.setuid(target.pw_uid)
            read_fd, write_fd = os.pipe()
            if grant:
                authorization = Authorization(); grants.append(authorization); os.write(write_fd, authorization.external.raw)
            os.close(write_fd)
            command = [str(app / 'Contents/MacOS/JustConnect'), mode]
            if not mode.startswith('--wire-'):
                command += [str(read_fd)] + ([owner] if owner else [])
            elif owner:
                command.append(owner)
            error = (output / ('client-' + str(len(processes)) + '.err')).open('wb')
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error,
                preexec_fn=ordinary, pass_fds=(read_fd,), cwd='/', env={'HOME': target.pw_dir, 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
            error.close(); os.close(read_fd); processes.append(process); return process

        def event(process, expected):
            assert select.select([process.stdout], [], [], 40)[0], 'Client event timed out'
            value = process.stdout.readline()
            assert value, f'Client exited before {expected}: {process.poll()}'
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
            assert process.wait(timeout=20) == 0, 'Native client failed'

        def withdrawn(interface):
            result = run('/sbin/route', '-n', 'get', '-inet', '198.18.0.6', check=False)
            return not re.search(r'^\s*interface:\s*' + re.escape(interface) + r'\s*$', result.stdout.decode(), re.M)

        try:
            run('/bin/launchctl', 'bootstrap', 'system', launch_path)
            wait_for(lambda: user_state.parent.exists(), 'Signed root daemon did not start')
            for mode in ('--wire-denied', '--wire-invalid-auth'):
                denied = start(mode); event(denied, 'wire-denied'); finish(denied)
            assert not user_state.exists(), 'Authorization denial created ownership or network state'
            for name, wrong_identity in [('wrong-id', False), ('wrong-certificate', True)]:
                copy = directory / (name + '.app'); shutil.copytree(bundle, copy, symlinks=True)
                if wrong_identity:
                    other, other_keychain = certificate(private, 'JustConnect foreign signing fixture'); keychains.append(other_keychain)
                    sign(copy, other, other_keychain, APP_ID)
                else:
                    sign(copy, identity, keychain, APP_ID + '.foreign')
                denied = start('--wire-untrusted', app=copy); event(denied, 'wire-denied'); finish(denied)
                assert not user_state.exists(), 'Untrusted signed executable created ownership storage'
            client = start('--roundtrip', grant=True); active = event(client, 'active')
            assert receipt(active['owner'], 'active')
            for mode, target in [('--wire-live', account), ('--wire-foreign', pwd.getpwnam('nobody'))]:
                denied = start(mode, owner=active['owner'], target=target); event(denied, 'wire-denied'); finish(denied)
                assert receipt(active['owner'], 'active') and not withdrawn(active['interface']), 'Foreign connection withdrew live ownership'
            client.stdin.write(b'restore\n'); client.stdin.flush(); event(client, 'restored'); finish(client)
            assert not (user_state / active['owner']).exists(), 'Confirmed restoration left an unacknowledged receipt'
            cancelled = str(uuid.uuid4())
            client = start('--cancel', grant=True, owner=cancelled); event(client, 'applying')
            wait_for(lambda: receipt(cancelled, 'active'), 'Cancellation did not reach real privileged apply')
            client.stdin.write(b'cancel\n'); client.stdin.flush(); event(client, 'restored'); finish(client)
            assert not list(user_state.iterdir()), 'Cancelled apply leaked ownership'
            client = start('--roundtrip', grant=True); active = event(client, 'active')
            client.kill(); client.wait(timeout=10)
            wait_for(lambda: receipt(active['owner'], 'restored') and withdrawn(active['interface']), 'Client EOF failed to restore owned capture')
            recovery = start('--recover', owner=active['owner']); event(recovery, 'restored'); finish(recovery)
            client = start('--roundtrip', grant=True); active = event(client, 'active')
            service = run('/bin/launchctl', 'print', 'system/' + SERVICE).stdout.decode()
            pid = re.search(r'^\s*pid = (\d+)\s*$', service, re.M); assert pid
            os.kill(int(pid[1]), signal.SIGKILL); event(client, 'lost')
            wait_for(lambda: receipt(active['owner'], 'restored') and withdrawn(active['interface']), 'New daemon did not restore capture while ordinary fd remained open')
            client.stdin.write(b'exit\n'); client.stdin.flush(); finish(client)
            recovery = start('--recover', owner=active['owner']); event(recovery, 'restored'); finish(recovery)
            assert not list(user_state.iterdir()), 'Recovered ownership was not acknowledged'
            print('PASS: signed root XPC, denied foreign identity and absent network rights, ordinary real UDP/fd, cancellation, EOF and daemon restart recovery', flush=True)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=10)
            run('/bin/launchctl', 'bootout', 'system/' + SERVICE, check=False)
            for grant in grants:
                grant.close()
            for keychain in keychains:
                run('/usr/bin/security', 'delete-keychain', keychain, check=False)
    wait_for(lambda: set(run('/sbin/ifconfig', '-l').stdout.decode().split()) == before, 'Owned utun survived completed fixture')
    if user_state.exists():
        assert not list(user_state.iterdir()), 'Preserve unresolved ownership evidence'
        user_state.rmdir()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, required=True)
    for name in ('helper', 'client', 'plist', 'deploy-tool', 'revision', 'output'):
        parser.add_argument('--' + name, required=True)
    main(parser.parse_args())
