"""Run the actual installed helper in private /usr, state and network namespaces."""

import argparse
import json
import os
from pathlib import Path
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
sys.path.insert(0, str(ROOT / 'scripts'))
import network_helper_package as package
from networkhelper_systemd import RecoveryTimer
from tundns_fixture import IsolatedResolver, OriginalDnsServer


def run(*arguments, **options):
    try:
        return subprocess.check_output(list(map(str, arguments)), text=True, timeout=30, **options)
    except subprocess.CalledProcessError as error:
        print(error.output, end='', flush=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--package', type=Path)
    source.add_argument('--stage', type=Path)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--development-qt', type=Path, help='local fixture only: copy SDK Core/DBus libraries into the private /usr')
    parser.add_argument('--client', type=Path, help='ordinary Qt caller built with the application SDK')
    parser.add_argument('--authorization-fixture', type=Path, help='namespace-only authorization broker fixture')
    parser.add_argument('--gateway', type=Path, help='native campus gateway test binary')
    parser.add_argument('--tun-adapter', type=Path, help='Qt/core TUN caller for the installed helper')
    args = parser.parse_args()
    assert os.geteuid() == 0 and args.uid != 0
    for name in ('net', 'mnt'):
        assert os.stat(f'/proc/thread-self/ns/{name}') != os.stat(f'/proc/1/ns/{name}'), f'refusing the host {name} namespace'
    assert not (args.package and args.development_qt), 'release package must load the actual distribution runtime'
    assert bool(args.client) == bool(args.authorization_fixture)
    assert bool(args.gateway) == bool(args.tun_adapter) and (not args.gateway or args.client)
    client = args.client.resolve(strict=True) if args.client else None
    broker = args.authorization_fixture.resolve(strict=True) if args.authorization_fixture else None
    gateway = args.gateway.resolve(strict=True) if args.gateway else None
    tun_adapter = args.tun_adapter.resolve(strict=True) if args.tun_adapter else None
    if args.package:
        files, report = package.inspect_package(args.package.resolve(strict=True), args.revision)
        report['mode'] = 'distribution-package'
    else:
        stage = args.stage.resolve(strict=True)
        paths = {str(path.relative_to(stage)) for path in stage.rglob('*') if path.is_file() or path.is_symlink()}
        assert paths == package.FILES and all(not (stage / name).is_symlink() for name in paths)
        files = {name: (stage / name).read_bytes() for name in paths}
        package.verify_policy(files[package.POLICY])
        assert files[package.DOCUMENTATION + 'source-revision.txt'] == (args.revision + '\n').encode()
        report = {'mode': 'development-stage', 'source_commit': args.revision}
    service, timer = package.verify_recovery_units(files)

    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
    account = pwd.getpwuid(args.uid)
    with tempfile.TemporaryDirectory(prefix='JustConnect-helper-install-test-') as temporary:
        temporary = Path(temporary)
        upper, work, state = (temporary / name for name in ('upper', 'work', 'state'))
        for path in (upper, work, state):
            path.mkdir(mode=0o755)
        run('mount', '--make-rprivate', '/')
        run('mount', '-t', 'overlay', 'overlay', '-o', f'lowerdir=/usr,upperdir={upper},workdir={work}', '/usr')
        run('mount', '--bind', state, '/var/lib')
        recovery = None
        caller_runtime = None
        try:
            for name, contents in files.items():
                path = Path('/') / name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with path.open('xb') as stream:
                    stream.write(contents)
                path.chmod(0o755 if name == package.EXECUTABLE else 0o644)
                assert path.stat().st_uid == 0 and not path.stat().st_mode & 0o7022
            if args.development_qt:
                # This supplies only the isolated local fixture, never the release package.
                library = args.development_qt.resolve(strict=True) / 'lib'
                pending = ['libQt6Core.so.6', 'libQt6DBus.so.6']
                copied = set()
                while pending:
                    name = pending.pop()
                    if name in copied:
                        continue
                    copied.add(name)
                    destination = Path('/usr/lib') / name
                    assert not destination.exists(), 'local fixture would replace an existing system library'
                    shutil.copyfile(library / name, destination)
                    destination.chmod(0o644)
                    dynamic = run('readelf', '-d', destination)
                    pending += [value for value in re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic) if (library / value).is_file() and value not in copied]
                report['development_libraries'] = sorted(copied)

            executable = Path(package.LAYOUT['executable'])
            dynamic = run('readelf', '-d', executable, env=environment)
            assert not re.search(r'\((?:RPATH|RUNPATH)\).*?\[[^\]]+\]', dynamic), 'installed helper retains a loader search path'
            qt = [name for name in re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic) if name.startswith('libQt')]
            assert set(qt) == {'libQt6Core.so.6', 'libQt6DBus.so.6'}, qt
            dependencies = run('ldd', executable, env=environment)
            assert 'not found' not in dependencies
            for name in re.findall(r'(/\S+)\s+\(0x', dependencies):
                path = Path(name).resolve(strict=True)
                assert path.is_relative_to('/usr/lib') or path.is_relative_to('/lib'), path
                assert path.stat().st_uid == 0 and not path.stat().st_mode & 0o022, path
            facts = json.loads(run(executable, '--version', env=environment, user=args.uid, group=account.pw_gid, extra_groups=()))
            assert facts['worker'] == 'network-helper' and facts['protocol'] == package.LAYOUT['protocol'] and facts['revision'] == args.revision
            for options in ({'user': args.uid, 'group': account.pw_gid, 'extra_groups': ()},
                            {'env': {**environment, 'PKEXEC_UID': str(args.uid)}}):
                result = subprocess.run([str(executable), '--recover-stale'], capture_output=True, timeout=5,
                                        **({'env': environment} | options))
                assert result.returncode == 1 and not result.stdout and not Path(package.LAYOUT['state_directory']).exists(), \
                    'system recovery accepted an ordinary/pkexec caller or wrote storage before authorization'
            if args.package:
                assert facts['source_state'] == 'clean', facts
            report.update(runtime=facts, dependencies=dependencies)
            uninstalled = executable.with_name(executable.name + '.fixture-copy')
            shutil.copyfile(executable, uninstalled)
            uninstalled.chmod(0o755)
            result = subprocess.run([str(uninstalled), '--recover-stale'], env=environment, capture_output=True, timeout=5)
            assert result.returncode == 1 and not result.stdout, 'system recovery accepted an alternate executable location'
            assert json.loads(run(uninstalled, '--version', env=environment, user=args.uid, group=account.pw_gid, extra_groups=())) == facts
            print('PASS: root-installed path and system Core/DBus runtime load without SDK/AppImage environment', flush=True)
            manager_root = temporary / 'manager-root'
            for name in ('usr/bin', 'usr/sbin', 'usr/lib', 'usr/lib64', 'usr/libexec', 'usr/local/lib', 'proc', 'dev', 'tmp', 'etc'):
                (manager_root / name).mkdir(parents=True, exist_ok=True)
            for name in ('bin', 'sbin', 'lib', 'lib64', 'usr/sbin', 'usr/lib64'):
                original = Path('/') / name
                destination = manager_root / name
                if original.is_symlink():
                    if destination.is_dir():
                        destination.rmdir()
                    destination.symlink_to(original.readlink())
            for path in (manager_root / 'var/lib', manager_root / package.LAYOUT['state_directory'].lstrip('/')):
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(executable, manager_root / package.EXECUTABLE)
            (manager_root / package.EXECUTABLE).chmod(0o755)
            for name in report.get('development_libraries', []):
                shutil.copyfile(Path('/usr/lib') / name, manager_root / 'usr/local/lib' / name)
            recovery = RecoveryTimer(package.LAYOUT, service, timer, manager_root, state, report.get('development_libraries', []))
            recovery.start(deferred=True)
            subprocess.run([sys.executable, '-B', str(ROOT / 'tests/platform/networkhelper_linux.py'), '--uid', str(args.uid),
                            '--helper', str(executable), '--installed', '--uninstalled-helper', str(uninstalled)], env=environment, check=True, timeout=60)
            assert not list(Path(package.LAYOUT['state_directory']).iterdir()), 'actual entry left operation records'
            if client:
                authorization = Path(package.LAYOUT['authorization_program'])
                if authorization.exists():
                    authorization.unlink()  # Only the private overlay is changed.
                shutil.copyfile(broker, authorization)
                authorization.chmod(0o4755)
                ip = lambda *values: run('ip', *values, env=environment)
                ip('link', 'add', 'helperorig0', 'type', 'dummy')
                ip('link', 'set', 'helperorig0', 'up')
                ip('address', 'add', '192.0.2.1/24', 'dev', 'helperorig0')
                ip('-4', 'route', 'add', 'default', 'dev', 'helperorig0')
                if gateway:
                    ip('link', 'set', 'lo', 'up')
                def inventory():
                    return tuple(value for family in ('-4', '-6') for value in
                                 (ip('-N', '-j', family, 'route', 'show', 'table', 'all'),
                                  ip('-N', '-j', family, 'rule', 'show'))) + (sorted(os.listdir('/sys/class/net')),)
                baseline = inventory()
                # Only the ordinary test process keeps its SDK loader environment; the product client strips it before authorization.
                caller_environment = {**environment, **{key: value for key, value in os.environ.items() if key == 'LD_LIBRARY_PATH'}}
                caller_runtime = tempfile.TemporaryDirectory(prefix='JustConnect-helper-caller-')
                os.chown(caller_runtime.name, args.uid, account.pw_gid)
                caller_environment['XDG_RUNTIME_DIR'] = caller_runtime.name
                caller_environment['XDG_DATA_HOME'] = caller_runtime.name + '/data'
                client_cases = []
                native_command = [str(gateway), '-test.v', '-test.timeout', '75s', '-test.run', '^TestNativeTUNHost$'] if gateway else None
                def native_handoff(process, owner, ready_path):
                    deadline = time.monotonic() + 10
                    while not ready_path.is_file() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    if not ready_path.is_file():
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                        output, errors = process.communicate(timeout=5)
                        raise AssertionError(f'native Qt/core never completed actual TUN traffic:\n{output}\n{errors}')
                    ready = json.loads(ready_path.read_text())
                    qt_pid = ready['pid']
                    qt_status = dict(line.split(':', 1) for line in Path(f'/proc/{qt_pid}/status').read_text().splitlines())
                    assert (owner is None or ready['owner'] == owner) and str(uuid.UUID(ready['owner'])) == ready['owner']
                    assert ready['generation'] and int(qt_status['PPid']) == process.pid
                    assert int(qt_status['Uid'].split()[0]) == args.uid and Path(f'/proc/{qt_pid}/exe').resolve() == tun_adapter
                    return qt_pid, os.pidfd_open(qt_pid)
                def owned_helper(qt_pid):
                    children = Path(f'/proc/{qt_pid}/task/{qt_pid}/children').read_text().split()
                    workers = [int(pid) for pid in children if Path(f'/proc/{pid}/exe').resolve() == executable]
                    assert len(workers) == 1, 'cannot identify the directly owned private-namespace fixture helper'
                    return workers[0]
                def call(scenario, mode='allow', owner=None):
                    owner = owner or str(uuid.uuid4())
                    result = run(client, scenario, owner, env=client_environment(scenario, mode),
                                 user=args.uid, group=account.pw_gid, extra_groups=())
                    print(result, end='', flush=True)
                    client_cases.append(scenario)
                    return owner
                def client_environment(scenario, mode='allow'):
                    values = {**caller_environment, 'JC_AUTH_TEST_MODE': mode}
                    if scenario.startswith('dns'):
                        values['DBUS_SYSTEM_BUS_ADDRESS'] = 'unix:path=/nonexistent-untrusted-dns-bus'
                    return values
                for scenario, mode in [('normal', 'allow'), ('extend-cancel', 'allow'), ('cancel-inspect', 'allow'), ('cancel-authorization', 'wait'),
                                       ('cancel-apply', 'allow'), ('denied', 'deny'), ('cancel-policy', 'cancel'), ('malformed', 'malformed')]:
                    call(scenario, mode)
                    assert inventory() == baseline, scenario
                    assert not list(Path(package.LAYOUT['state_directory']).iterdir()), scenario
                ip('route', 'add', '198.18.5.0/24', 'dev', 'helperorig0', 'proto', 'static', 'metric', '7')
                before_failure = inventory()
                call('partial')
                assert inventory() == before_failure and not list(Path(package.LAYOUT['state_directory']).iterdir())
                ip('route', 'del', '198.18.5.0/24', 'dev', 'helperorig0', 'metric', '7')
                ip('route','add','198.18.6.7/32','dev','helperorig0','proto','static','metric','7')
                before_failure = inventory()
                call('extend-partial')
                assert inventory() == before_failure and not list(Path(package.LAYOUT['state_directory']).iterdir())
                ip('route','del','198.18.6.7/32','dev','helperorig0','metric','7')
                ip('route','add','198.18.7.0/24','dev','helperorig0','proto','static','metric','7')
                before_failure = inventory()
                call('routes-partial')
                assert inventory() == before_failure and not list(Path(package.LAYOUT['state_directory']).iterdir())
                ip('route','del','198.18.7.0/24','dev','helperorig0','metric','7')
                owner = call('destroy')
                deadline = time.monotonic() + 10
                while inventory() != baseline and time.monotonic() < deadline:
                    time.sleep(0.02)
                assert inventory() == baseline, 'client destruction left native network ownership'
                receipts = list(Path(package.LAYOUT['state_directory']).glob('*/source.json'))
                assert len(receipts) == 1 and json.loads(receipts[0].read_text())['phase'] == 'restored'
                call('cleanup', owner=owner)
                call('cleanup', owner=owner)
                assert inventory() == baseline and not list(Path(package.LAYOUT['state_directory']).iterdir())
                owner = str(uuid.uuid4())
                ready_path = Path(caller_runtime.name) / 'helper-loss.json'
                crash_environment = {**caller_environment, 'JC_AUTH_TEST_MODE': 'allow'}
                if gateway:
                    crash_environment.update(JC_NATIVE_TUN_HOST=str(tun_adapter), JC_NATIVE_TUN_HELPER_OWNER=owner,
                                             JC_NATIVE_TUN_READY=str(ready_path), JC_NATIVE_TUN_SCENARIO='helper-loss')
                process = subprocess.Popen(native_command if gateway else [str(client), 'crash', owner],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                           env=crash_environment, user=args.uid, start_new_session=bool(gateway),
                                           group=account.pw_gid, extra_groups=())
                qt_descriptor = None
                try:
                    qt_pid = process.pid
                    if gateway:
                        qt_pid, qt_descriptor = native_handoff(process, owner, ready_path)
                    else:
                        assert select.select([process.stdout], [], [], 10)[0], 'Qt crash fixture never reached device handoff'
                        assert process.stdout.readline().strip() == f'READY: active helper {owner}'
                    os.kill(owned_helper(qt_pid), signal.SIGKILL)
                    output, errors = process.communicate(timeout=15)
                    assert process.returncode == 0, (output, errors)
                    if gateway:
                        assert '--- PASS: TestNativeTUNHost' in output, 'native helper-loss data path was not verified'
                    print(output, end='', flush=True)
                    client_cases.append('crash')
                finally:
                    if process.poll() is None:
                        if gateway:
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                        process.communicate(timeout=5)
                    if qt_descriptor is not None:
                        if not select.select([qt_descriptor], [], [], 0)[0]:
                            signal.pidfd_send_signal(qt_descriptor, signal.SIGKILL)
                        assert select.select([qt_descriptor], [], [], 5)[0]
                        os.close(qt_descriptor)
                assert inventory() == baseline and not list(Path(package.LAYOUT['state_directory']).iterdir())
                if gateway:
                    native_environment = {**caller_environment, 'JC_AUTH_TEST_MODE': 'allow',
                                          'JC_NATIVE_TUN_HOST': str(tun_adapter), 'JC_NATIVE_TUN_HELPER_OWNER': str(uuid.uuid4())}
                    output = run(*native_command, env=native_environment, user=args.uid,
                                 group=account.pw_gid, extra_groups=())
                    assert '--- PASS: TestNativeTUNHost' in output, 'native Qt/core handoff was not verified'
                    print(output, end='', flush=True)
                    assert inventory() == baseline and not list(Path(package.LAYOUT['state_directory']).iterdir()), \
                        'Qt/core/helper stop or destruction left network ownership'
                    client_cases.append('core-tun')
                    report['core_tun'] = {'normal_sessions': 2, 'helper_loss_sessions': 2,
                                          'handoff': 'ordinary Qt caller through installed helper and formal C ABI',
                                          'helper_loss': 'client fd revoked while core reference survives; core stops before fresh authorized recovery',
                                          'traffic': 'native TCP, UDP and empty datagrams; stop/restart/destruction',
                                          'inventory': 'IPv4/IPv6 routes/rules and interfaces restored'}
                def managed(native_core, dns_bus=None):
                    baseline = inventory()
                    recovery.stop()
                    recovery.start(dns_bus=dns_bus)
                    owner = str(uuid.uuid4())
                    ready_path = Path(caller_runtime.name) / 'active-core.json'
                    ready_path.unlink(missing_ok=True)
                    scenario = 'dns-managed' if dns_bus else 'managed'
                    managed_environment = client_environment('managed' if native_core else scenario)
                    if native_core:
                        managed_environment.update(JC_NATIVE_TUN_HOST=str(tun_adapter), JC_NATIVE_TUN_HELPER_OWNER=owner,
                                                   JC_NATIVE_TUN_READY=str(ready_path), JC_NATIVE_TUN_SCENARIO='managed')
                        if dns_bus:
                            managed_environment['JC_NATIVE_TUN_DNS'] = '1'
                    process = subprocess.Popen(native_command if native_core else [str(client), scenario, owner],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                               env=managed_environment, user=args.uid, start_new_session=native_core,
                                               group=account.pw_gid, extra_groups=())
                    worker_descriptor = None
                    qt_descriptor = None
                    try:
                        qt_pid = process.pid
                        if native_core:
                            qt_pid, qt_descriptor = native_handoff(process, owner, ready_path)
                        else:
                            assert select.select([process.stdout], [], [], 10)[0], 'managed fixture never reached handoff'
                            assert process.stdout.readline().strip() == f'READY: managed helper {owner}'
                        worker = owned_helper(qt_pid)
                        worker_descriptor = os.pidfd_open(worker)
                        held = inventory()
                        deadline = time.monotonic() + 15
                        observed = None
                        while time.monotonic() < deadline:
                            observed = recovery.invocation_summary()
                            if observed and (observed['live'] == 1 or observed['failed']):
                                break
                            time.sleep(0.05)
                        assert observed and observed['live'] == 1 and observed['restored'] == observed['failed'] == 0, observed
                        assert inventory() == held, 'system timer disturbed an actively held connection'
                        signal.pidfd_send_signal(worker_descriptor, signal.SIGKILL)
                        process.kill()
                        if qt_descriptor is not None:
                            signal.pidfd_send_signal(qt_descriptor, signal.SIGKILL)
                        process.communicate(timeout=5)
                        assert process.returncode == -signal.SIGKILL
                        deadline = time.monotonic() + 35
                        receipt = Path(package.LAYOUT['state_directory']) / f'{args.uid}-{owner}' / 'source.json'
                        while time.monotonic() < deadline:
                            observed = recovery.invocation_summary()
                            if inventory() == baseline and json.loads(receipt.read_text())['phase'] == 'restored' \
                                    and observed and observed['restored'] == 1 and observed['failed'] == 0:
                                break
                            time.sleep(0.05)
                        assert inventory() == baseline and json.loads(receipt.read_text())['phase'] == 'restored', observed
                        assert observed and observed['restored'] == 1 and observed['failed'] == 0, observed
                        client_cases.append(scenario)
                        if native_core:
                            fault = 'owned Qt/core and helper both SIGKILL after native TCP/UDP' + (' and actual core DNS' if dns_bus else '')
                        elif dns_bus:
                            fault = 'ordinary Qt DNS caller and helper both SIGKILL after actual system query'
                        else:
                            fault = 'owned fixtures both SIGKILL; no GUI command initiated recovery'
                        report['system_dns_recovery' if dns_bus else 'system_recovery'] = {
                            'slice': recovery.property('service', 'Slice'), 'invocation': recovery.property('service', 'InvocationID'),
                            'summary': observed, 'gui_and_helper': fault}
                        print('PASS: real system timer preserves live ownership and restores after both GUI/helper SIGKILL' + (' with owned DNS' if dns_bus else ''), flush=True)
                    finally:
                        if process.poll() is None:
                            if native_core:
                                os.killpg(process.pid, signal.SIGKILL)
                            else:
                                process.kill()
                            process.communicate(timeout=5)
                        if qt_descriptor is not None:
                            if not select.select([qt_descriptor], [], [], 0)[0]:
                                signal.pidfd_send_signal(qt_descriptor, signal.SIGKILL)
                            assert select.select([qt_descriptor], [], [], 5)[0], 'owned Qt/core retained its TUN references'
                            os.close(qt_descriptor)
                        if worker_descriptor is not None:
                            assert select.select([worker_descriptor], [], [], 35)[0], 'owned helper did not finish EOF recovery'
                            os.close(worker_descriptor)
                        recovery.stop()
                    call('cleanup', owner=owner)
                managed(bool(gateway))
                with IsolatedResolver(temporary / 'resolver', environment) as resolver:
                    resolver.start()
                    with OriginalDnsServer(resolver, 'helperorig0') as original:
                        dns_baseline = inventory()
                        run('/usr/bin/resolvectl', 'dns', 'helperorig0', '192.0.2.53', env=environment)
                        run('/usr/bin/resolvectl', 'domain', 'helperorig0', '~.', '~original.test', env=environment)
                        def original_dns():
                            return [run('/usr/bin/resolvectl', key, 'helperorig0', env=environment)
                                    for key in ('dns', 'domain', 'default-route')]
                        dns_settings = original_dns()
                        recovery.start(deferred=True, dns_bus=resolver.socket)
                        try:
                            call('dns')
                            assert inventory() == dns_baseline and original_dns() == dns_settings
                        finally:
                            recovery.stop()
                        if gateway:
                            dns_environment = {**caller_environment, 'JC_AUTH_TEST_MODE': 'allow',
                                               'JC_NATIVE_TUN_HOST': str(tun_adapter), 'JC_NATIVE_TUN_HELPER_OWNER': str(uuid.uuid4()),
                                               'JC_NATIVE_TUN_DNS': '1'}
                            recovery.start(deferred=True, dns_bus=resolver.socket)
                            try:
                                output = run(*native_command, env=dns_environment, user=args.uid,
                                             group=account.pw_gid, extra_groups=())
                                assert output.count('PASS: ordinary getaddrinfo through installed helper and core TUN DNS') == 2, output
                                print(output, end='', flush=True)
                                client_cases.append('core-dns')
                                application_environment = {**dns_environment, 'JC_NATIVE_NETWORK_SESSION': '1'}
                                ip('route','add','198.18.0.4/30','dev','helperorig0')
                                try:
                                    output = run(*native_command, env={**application_environment, 'JC_NATIVE_NETWORK_CHOICES': '1'}, user=args.uid,
                                                 group=account.pw_gid, extra_groups=())
                                finally:
                                    ip('route','del','198.18.0.4/30','dev','helperorig0')
                                assert 'via application network startup recovery' in output, output
                                print(output, end='', flush=True)
                                client_cases.append('application-network')
                                report['application_network'] = {'sessions': 2, 'startup': 'write-ahead UUID without privileged record',
                                    'data': 'ordinary DNS, TCP and UDP; exact campus/original address choices and capture withdrawal', 'stop': 'owned network before core; hint and fd released'}
                                ready_path = Path(caller_runtime.name) / 'application-helper-loss.json'
                                ready_path.unlink(missing_ok=True)
                                process = subprocess.Popen(native_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                                           env={**application_environment, 'JC_NATIVE_NETWORK_HELPER_LOSS': '1',
                                                                'JC_NATIVE_TUN_READY': str(ready_path)}, user=args.uid,
                                                           group=account.pw_gid, extra_groups=(), start_new_session=True)
                                qt_descriptor = None
                                try:
                                    qt_pid, qt_descriptor = native_handoff(process, None, ready_path)
                                    worker = owned_helper(qt_pid)
                                    worker_descriptor = os.pidfd_open(worker)
                                    try:
                                        signal.pidfd_send_signal(worker_descriptor, signal.SIGKILL)
                                    finally:
                                        os.close(worker_descriptor)
                                    output, errors = process.communicate(timeout=30)
                                    assert process.returncode == 0, output + errors
                                    assert 'application helper loss releases core/device before explicit recovery and fresh restart' in output, output
                                    print(output, end='', flush=True)
                                    client_cases.append('application-helper-loss')
                                    report['application_network']['helper_loss'] = 'helper SIGKILL; release core fd, retain responsibility until explicit recovery, then fresh ready session'
                                finally:
                                    if process.poll() is None:
                                        os.killpg(process.pid, signal.SIGKILL)
                                        process.communicate(timeout=5)
                                    if qt_descriptor is not None:
                                        if not select.select([qt_descriptor], [], [], 0)[0]:
                                            signal.pidfd_send_signal(qt_descriptor, signal.SIGKILL)
                                        assert select.select([qt_descriptor], [], [], 5)[0]
                                        os.close(qt_descriptor)
                            finally:
                                recovery.stop()
                            assert inventory() == dns_baseline and original_dns() == dns_settings
                        managed(native_core=bool(gateway), dns_bus=resolver.socket)
                        assert inventory() == dns_baseline and original_dns() == dns_settings
                        report['owned_dns'] = {'provider': 'actual isolated resolved',
                                               'entry': 'clean installed helper via ordinary Qt authorization caller',
                                               'query': 'actual ordinary getaddrinfo through ' + ('core TUN DNS' if gateway else 'authenticated TUN fd fixture'),
                                               'system_manager': 'real system.slice timer, production CAP_NET_ADMIN sandbox',
                                               'injected_bus': 'untrusted caller address ignored',
                                               'original_interface': 'DNS settings and IPv4/IPv6 inventory unchanged'}
                        if gateway:
                            assert set(original.queries) == {'public.test', 'host.original.test'}, original.queries
                            report['owned_dns']['original_queries'] = original.queries
                            report['owned_dns']['original_families'] = 'A and AAAA through original DNS'
                            report['owned_dns']['localhost'] = 'ordinary AF_UNSPEC lookup and local TCP connection remain loopback'
                assert inventory() == baseline and not list(Path(package.LAYOUT['state_directory']).iterdir())
                call('guard-blocked')
                assert inventory() == baseline and not list(Path(package.LAYOUT['state_directory']).iterdir())
                other = subprocess.Popen(['unshare', '--net', '--', '/usr/bin/sleep', '60'], env=environment)
                try:
                    deadline = time.monotonic() + 3
                    while os.stat(f'/proc/{other.pid}/ns/net') == os.stat('/proc/thread-self/ns/net') and time.monotonic() < deadline:
                        time.sleep(0.01)
                    assert os.stat(f'/proc/{other.pid}/ns/net') != os.stat('/proc/thread-self/ns/net')
                    recovery.start(deferred=True, namespace_process=other.pid)
                    call('guard-blocked')
                    assert inventory() == baseline and not list(Path(package.LAYOUT['state_directory']).iterdir())
                finally:
                    recovery.stop()
                    other.kill()
                    other.wait(timeout=5)
                print('PASS: disabled timer and another private recovery namespace refuse apply without network writes', flush=True)
                ip('link', 'del', 'helperorig0')
                report['qt_client'] = {'scenarios': len(client_cases), 'cases': client_cases, 'gui_uid': args.uid, 'broker': 'namespace-only setuid fixture',
                                       'desktop_polkit': 'not exercised'}
            print('REPORT: ' + json.dumps(report, sort_keys=True), flush=True)
        finally:
            if recovery:
                recovery.stop()
            if caller_runtime:
                caller_runtime.cleanup()
            run('umount', '/var/lib')
            run('umount', '--lazy', '/usr')


if __name__ == '__main__':
    main()
