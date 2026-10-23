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


def run(*arguments, **options):
    return subprocess.check_output(list(map(str, arguments)), text=True, timeout=30, **options)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--package', type=Path)
    source.add_argument('--stage', type=Path)
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--development-qt', type=Path, help='local fixture only: copy SDK Core libraries into the private /usr')
    parser.add_argument('--client', type=Path, help='ordinary Qt caller built with the application SDK')
    parser.add_argument('--authorization-fixture', type=Path, help='namespace-only authorization broker fixture')
    args = parser.parse_args()
    assert os.geteuid() == 0 and args.uid != 0
    for name in ('net', 'mnt'):
        assert os.stat(f'/proc/thread-self/ns/{name}') != os.stat(f'/proc/1/ns/{name}'), f'refusing the host {name} namespace'
    assert not (args.package and args.development_qt), 'release package must load the actual distribution runtime'
    assert bool(args.client) == bool(args.authorization_fixture)
    client = args.client.resolve(strict=True) if args.client else None
    broker = args.authorization_fixture.resolve(strict=True) if args.authorization_fixture else None
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
                pending = ['libQt6Core.so.6']
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
            assert qt == ['libQt6Core.so.6'], qt
            dependencies = run('ldd', executable, env=environment)
            assert 'not found' not in dependencies
            for name in re.findall(r'(/\S+)\s+\(0x', dependencies):
                path = Path(name).resolve(strict=True)
                assert path.is_relative_to('/usr/lib') or path.is_relative_to('/lib'), path
                assert path.stat().st_uid == 0 and not path.stat().st_mode & 0o022, path
            facts = json.loads(run(executable, '--version', env=environment, user=args.uid, group=account.pw_gid, extra_groups=()))
            assert facts['worker'] == 'network-helper' and facts['protocol'] == 2 and facts['revision'] == args.revision
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
            print('PASS: root-installed path and system Core runtime load without SDK/AppImage environment', flush=True)
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
                def inventory():
                    return (ip('-N', '-j', '-4', 'route', 'show', 'table', 'all'),
                            ip('-N', '-j', '-4', 'rule', 'show'), sorted(os.listdir('/sys/class/net')))
                baseline = inventory()
                # Only the ordinary test process keeps its SDK loader environment; the product client strips it before authorization.
                caller_environment = {**environment, **{key: value for key, value in os.environ.items() if key == 'LD_LIBRARY_PATH'}}
                def call(scenario, mode='allow', owner=None):
                    owner = owner or str(uuid.uuid4())
                    result = run(client, scenario, owner, env={**caller_environment, 'JC_AUTH_TEST_MODE': mode},
                                 user=args.uid, group=account.pw_gid, extra_groups=())
                    print(result, end='', flush=True)
                    return owner
                for scenario, mode in [('normal', 'allow'), ('cancel-inspect', 'allow'), ('cancel-authorization', 'wait'),
                                       ('cancel-apply', 'allow'), ('denied', 'deny'), ('cancel-policy', 'cancel'), ('malformed', 'malformed')]:
                    call(scenario, mode)
                    assert inventory() == baseline, scenario
                    assert not list(Path(package.LAYOUT['state_directory']).iterdir()), scenario
                ip('route', 'add', '198.18.5.0/24', 'dev', 'helperorig0', 'proto', 'static', 'metric', '7')
                before_failure = inventory()
                call('partial')
                assert inventory() == before_failure and not list(Path(package.LAYOUT['state_directory']).iterdir())
                ip('route', 'del', '198.18.5.0/24', 'dev', 'helperorig0', 'metric', '7')
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
                process = subprocess.Popen([str(client), 'crash', owner], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                           env={**caller_environment, 'JC_AUTH_TEST_MODE': 'allow'}, user=args.uid,
                                           group=account.pw_gid, extra_groups=())
                try:
                    assert select.select([process.stdout], [], [], 10)[0], 'Qt crash fixture never reached device handoff'
                    assert process.stdout.readline().strip() == f'READY: active helper {owner}'
                    children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
                    workers = [int(pid) for pid in children if Path(f'/proc/{pid}/exe').resolve() == executable]
                    assert len(workers) == 1, 'cannot identify the directly owned private-namespace fixture helper'
                    os.kill(workers[0], signal.SIGKILL)
                    output, errors = process.communicate(timeout=15)
                    assert process.returncode == 0, (output, errors)
                    print(output, end='', flush=True)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=5)
                assert inventory() == baseline and not list(Path(package.LAYOUT['state_directory']).iterdir())
                ip('link', 'del', 'helperorig0')
                report['qt_client'] = {'scenarios': 12, 'gui_uid': args.uid, 'broker': 'namespace-only setuid fixture',
                                       'desktop_polkit': 'not exercised'}
            print('REPORT: ' + json.dumps(report, sort_keys=True), flush=True)
        finally:
            run('umount', '/var/lib')
            run('umount', '--lazy', '/usr')


if __name__ == '__main__':
    main()
