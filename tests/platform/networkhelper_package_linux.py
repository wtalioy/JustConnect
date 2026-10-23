"""Run the actual installed helper in private /usr, state and network namespaces."""

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

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
    args = parser.parse_args()
    assert os.geteuid() == 0 and args.uid != 0
    for name in ('net', 'mnt'):
        assert os.stat(f'/proc/thread-self/ns/{name}') != os.stat(f'/proc/1/ns/{name}'), f'refusing the host {name} namespace'
    assert not (args.package and args.development_qt), 'release package must load the actual distribution runtime'
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
            assert facts['worker'] == 'network-helper' and facts['protocol'] == 1 and facts['revision'] == args.revision
            if args.package:
                assert facts['source_state'] == 'clean', facts
            report.update(runtime=facts, dependencies=dependencies)
            uninstalled = executable.with_name(executable.name + '.fixture-copy')
            shutil.copyfile(executable, uninstalled)
            uninstalled.chmod(0o755)
            assert json.loads(run(uninstalled, '--version', env=environment, user=args.uid, group=account.pw_gid, extra_groups=())) == facts
            print('PASS: root-installed path and system Core runtime load without SDK/AppImage environment', flush=True)
            subprocess.run([sys.executable, '-B', str(ROOT / 'tests/platform/networkhelper_linux.py'), '--uid', str(args.uid),
                            '--helper', str(executable), '--installed', '--uninstalled-helper', str(uninstalled)], env=environment, check=True, timeout=60)
            assert not list(Path(package.LAYOUT['state_directory']).iterdir()), 'actual entry left operation records'
            print('REPORT: ' + json.dumps(report, sort_keys=True), flush=True)
        finally:
            run('umount', '/var/lib')
            run('umount', '--lazy', '/usr')


if __name__ == '__main__':
    main()
