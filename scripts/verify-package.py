"""Run the installed application's offline ABI check and audit native dependencies."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def run(*args, env=None, cwd=None, timeout=60):
    result = subprocess.run(list(map(str, args)), env=env, cwd=cwd, check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: '
                           + result.stderr.decode('utf-8', errors='replace')
                           + result.stdout.decode('utf-8', errors='replace'))
    return result.stdout.decode('utf-8', errors='replace')


def check_windows_dns_reader(root, env):
    reader = root / 'JustConnectDnsReader.exe'
    if not reader.is_file():
        raise RuntimeError('Missing packaged native DNS reader')
    facts = json.loads(run(reader, env=env, timeout=10))
    if (not isinstance(facts, dict) or set(facts) != {'interfaces', 'clients', 'global', 'nrpt', 'doh_supported', 'doh'}
            or any(not isinstance(facts[key], list) for key in ('interfaces', 'clients', 'nrpt', 'doh'))
            or not isinstance(facts['global'], dict) or not isinstance(facts['doh_supported'], bool)):
        raise RuntimeError('Packaged DNS reader did not return complete native facts')
    return {'interfaces': len(facts['interfaces']), 'effective_nrpt': len(facts['nrpt'])}


def check_proxy_recovery(root, env):
    worker = root / ('JustConnectProxyRecovery.exe' if sys.platform == 'win32' else 'JustConnectProxyRecovery')
    if not worker.is_file():
        raise RuntimeError('Missing packaged system proxy recovery worker')
    facts = json.loads(run(worker, '--version', env=env, timeout=5))
    if (not isinstance(facts, dict) or set(facts) != {'worker', 'protocol', 'qt'} or facts['worker'] != 'system-proxy-recovery'
            or type(facts['protocol']) is not int or facts['protocol'] != 2
            or not isinstance(facts['qt'], str) or not facts['qt'].startswith('6.')):
        raise RuntimeError('Packaged system proxy recovery worker failed its runtime check')
    return facts


def clean_environment():
    env = {k: v for k, v in os.environ.items() if not k.startswith(
        ('QT', 'QML', 'LD_', 'DYLD_'))}
    env['LC_ALL'] = 'C'
    env['PATH'] = (str(Path(os.environ['SystemRoot']) / 'System32') if sys.platform == 'win32'
                   else '/usr/bin:/bin:/usr/sbin:/sbin')
    return env


def version(value):
    parts = tuple(map(int, value.split('.')))
    return parts + (0,) * (4 - len(parts))


def inside(path, root):
    return path.resolve().is_relative_to(root.resolve())


def validate_report(report, revision, application_version, system, arch):
    contract = json.loads((ROOT / 'corelib/abi/contract.json').read_text())
    required_go = next(line.split()[1] for line in (ROOT / 'corelib/go.mod').read_text().splitlines()
                       if line.startswith('go '))
    core = report['core']
    build = core['build']
    if not (report['ok'] is True and core['test_driver'] is False
            and core['abi_version'] == contract['abi_version']
            and core['capabilities']['embedded_vpn'] is True
            and report['application_version'] == application_version
            and build['revision'] == revision and build['source_state'] == 'clean'
            and build['upstream_commit'] == contract['upstream_commit']
            and build['go_version'].split('-X:')[0] == 'go' + required_go
            and build['os'] == system and build['arch'] == arch):
        raise RuntimeError('Packaged ABI, production capability or build provenance mismatch')


def linux_audit(files, root, arch, env):
    evidence, required = [], set()
    loader_env = dict(env, LD_LIBRARY_PATH=str(root / 'usr/lib'))
    for path in files:
        header = run('readelf', '-h', path, env=env)
        expected = 'AArch64' if arch == 'arm64' else 'Advanced Micro Devices X86-64'
        if expected not in header:
            raise RuntimeError(f'Wrong ELF architecture: {path}')
        dynamic = run('readelf', '-d', path, env=env)
        for entry in re.findall(r'\((?:RUNPATH|RPATH)\).*?\[(.*?)\]', dynamic):
            if any(item.startswith('/') for item in entry.split(':')):
                raise RuntimeError(f'Non-relocatable ELF search path: {path}: {entry}')
        dependencies = ''
        if '(NEEDED)' in dynamic:
            dependencies = run('ldd', path, env=loader_env)
            if 'not found' in dependencies:
                raise RuntimeError(f'Missing dependency: {path}\n{dependencies}')
            for dependency in re.findall(r'(?:=>\s*)?(/[^\s]+)', dependencies):
                resolved = Path(dependency).resolve()
                if not inside(resolved, root):
                    if not (inside(resolved, Path('/usr/lib')) or inside(resolved, Path('/lib'))):
                        raise RuntimeError(f'Dependency outside package/system: {dependency}')
                    if resolved.name.startswith('libQt'):
                        raise RuntimeError(f'Qt dependency supplied by host: {dependency}')
        versions = run('readelf', '--version-info', '-W', path, env=env)
        needs = versions.partition('Version needs section')[2]
        required.update(re.findall(r'Name: (GLIBC(?:XX)?_[0-9.]+)', needs))
        evidence.append({'file': str(path.relative_to(root)), 'dependencies': dependencies})
    glibc = max((x.removeprefix('GLIBC_') for x in required if x.startswith('GLIBC_')),
                key=version, default='0')
    host = run('getconf', 'GNU_LIBC_VERSION', env=env).split()[1]
    if version(glibc) > version(host):
        raise RuntimeError(f'Package needs glibc {glibc}; host has {host}')
    return {'minimum_glibc': glibc, 'host_glibc': host,
            'required_symbol_versions': sorted(required), 'files': evidence}


def macos_signature(path, env):
    return subprocess.run(['codesign', '-dv', '--verbose=4', str(path)], env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stderr.decode('utf-8')


def macos_audit(files, root, arch, env, signed):
    evidence, minimum = [], '0'
    for path in files:
        expected = 'arm64' if arch == 'arm64' else 'x86_64'
        if run('lipo', '-archs', path, env=env).strip() != expected:
            raise RuntimeError(f'Wrong Mach-O architecture: {path}')
        commands = run('otool', '-l', path, env=env)
        rpaths = re.findall(r'\bpath (.*?) \(offset', commands)
        for rpath in rpaths:
            if rpath.startswith('/') and not rpath.startswith(('/System/Library/', '/usr/lib/')):
                raise RuntimeError(f'Non-relocatable Mach-O search path: {path}: {rpath}')
        for block in commands.split('Load command '):
            if re.search(r'cmd LC_(BUILD_VERSION|VERSION_MIN_MACOSX)\b', block):
                match = re.search(r'^\s+(?:minos|version)\s+([0-9.]+)', block, re.M)
                if match and version(match[1]) > version(minimum):
                    minimum = match[1]
        executable_dir = path.parent if path.parent.name == 'MacOS' else root / 'Contents/MacOS'
        dependencies = run('otool', '-L', path, env=env)
        for line in dependencies.splitlines()[1:]:
            dependency = line.strip().split(' (', 1)[0]
            if dependency.startswith(('/System/Library/', '/usr/lib/')):
                continue
            candidates = [Path(dependency.replace('@loader_path', str(path.parent))
                               .replace('@executable_path', str(executable_dir)))]
            if dependency.startswith('@rpath/'):
                suffix = dependency.removeprefix('@rpath/')
                candidates = [root / 'Contents/Frameworks' / suffix]
                for rpath in rpaths:
                    candidates.append(Path(rpath.replace('@loader_path', str(path.parent))
                                           .replace('@executable_path', str(executable_dir))) / suffix)
            if not any(candidate.exists() and inside(candidate, root) for candidate in candidates):
                raise RuntimeError(f'Dependency outside bundle/system: {path}: {dependency}')
        evidence.append({'file': str(path.relative_to(root)), 'dependencies': dependencies, 'rpaths': rpaths})
    declared = plistlib.loads((root / 'Contents/Info.plist').read_bytes())['LSMinimumSystemVersion']
    if version(minimum) > version(declared) or version(declared) > version(platform.mac_ver()[0]):
        raise RuntimeError(f'Invalid macOS floor: declared {declared}, binaries {minimum}')
    run('codesign', '--verify', '--deep', '--strict', root, env=env)
    signature = macos_signature(root, env)
    if signed and ('Signature=adhoc' in signature or 'Authority=Developer ID Application:' not in signature):
        raise RuntimeError('Developer ID signature required')
    app_id = plistlib.loads((root / 'Contents/Info.plist').read_bytes())['CFBundleIdentifier']
    if 'Identifier=' + app_id not in signature.splitlines():
        raise RuntimeError('Application signing identifier differs from its bundle')
    return {'minimum_macos': declared, 'binary_minimum': minimum, 'signature': signature, 'files': evidence,
            'network_helper': check_macos_network_helper(root, env, signed)}


def check_macos_network_helper(root, env, signed):
    layout = json.loads((ROOT / 'resource/network-helper-macos.json').read_text())
    identifier = plistlib.loads((root / 'Contents/Info.plist').read_bytes())['CFBundleIdentifier'] + layout['service_suffix']
    helper = root / 'Contents/MacOS' / layout['executable']
    launch = plistlib.loads((root / 'Contents/Library/LaunchDaemons' / (identifier + '.plist')).read_bytes())
    if launch != {'Label': identifier, 'BundleProgram': 'Contents/MacOS/' + layout['executable'], 'MachServices': {identifier: True},
                  'UserName': 'root', 'RunAtLoad': True, 'KeepAlive': {'SuccessfulExit': False}, 'ProcessType': 'Adaptive'}:
        raise RuntimeError('Packaged network daemon expands its fixed privilege contract')
    facts = json.loads(run(helper, '--version', env=env, timeout=10))
    if (not isinstance(facts, dict) or set(facts) != {'protocol', 'storage_version', 'revision', 'source_state', 'identity_ready'}
            or type(facts['protocol']) is not int or type(facts['storage_version']) is not int or type(facts['identity_ready']) is not bool
            or facts['protocol'] != layout['protocol'] or facts['storage_version'] != layout['storage_version']
            or facts['revision'] != (root / 'Contents/Resources/source-revision.txt').read_text().strip()
            or facts['source_state'] != 'clean' or (signed and not facts['identity_ready'])):
        raise RuntimeError('Packaged network helper has mismatched provenance or signing identity')
    if 'Identifier=' + identifier not in macos_signature(helper, env).splitlines():
        raise RuntimeError('Packaged network helper lost its signing identifier')
    dependencies = run('otool', '-L', helper, env=env)
    if any(name in dependencies for name in ('QtNetwork', 'QtWidgets', 'QtWebEngine', 'justconnect_core')):
        raise RuntimeError('Privileged network helper links application/data-plane libraries')
    return facts


def windows_audit(files, root, arch):
    evidence = []
    system = Path(os.environ['SystemRoot']) / 'System32'
    for path in files:
        with path.open('rb') as stream:
            stream.seek(0x3c)
            offset = int.from_bytes(stream.read(4), 'little')
            stream.seek(offset)
            header = stream.read(96)
        machine = int.from_bytes(header[4:6], 'little')
        if header[:4] != b'PE\0\0' or machine != (0xaa64 if arch == 'arm64' else 0x8664):
            raise RuntimeError(f'Wrong PE architecture: {path}')
        imports = run('llvm-readobj', '--coff-imports', path)
        dependencies = {}
        for name in re.findall(r'^\s+Name: (\S+)', imports, re.M):
            candidates = [path.parent / name, root / name]
            bundled = next((p for p in candidates if p.is_file()), None)
            if bundled:
                dependencies[name] = str(bundled.relative_to(root))
            elif (system / name).is_file() or name.lower().startswith(('api-ms-win-', 'ext-ms-win-')):
                dependencies[name] = 'Windows System32/API set'
            else:
                raise RuntimeError(f'Missing bundled/system DLL: {path}: {name}')
        floors = {name: '.'.join(str(int.from_bytes(header[x:x+2], 'little')) for x in offsets)
                  for name, offsets in [('pe_os_version', (64, 66)), ('pe_subsystem_version', (72, 74))]}
        host_version = sys.getwindowsversion()
        if any(version(value) > version(f'{host_version.major}.{host_version.minor}') for value in floors.values()):
            raise RuntimeError(f'PE requires newer Windows: {path}: {floors}')
        evidence.append({'file': str(path.relative_to(root)), 'dependencies': dependencies, **floors})
    return {'files': evidence}


def windows_signature(path):
    # Use the same PowerShell host as CI, including its compatible module paths.
    command = ("[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); "
               "$s = Get-AuthenticodeSignature -LiteralPath '"
               + str(path).replace("'", "''") + "'; $s.Status.ToString()")
    return run('pwsh', '-NoProfile', '-Command', command).strip()


def check_windows_webengine(root, probe, env):
    locales = root / 'translations/qtwebengine_locales'
    languages = ('en-US', 'zh-CN')
    for language in languages:
        if not (locales / f'{language}.pak').is_file():
            raise RuntimeError(f'Missing WebEngine locale: {language}')
    descriptor, name = tempfile.mkstemp(prefix='webengine-check-', suffix='.exe', dir=root)
    os.close(descriptor)
    installed_probe = Path(name)
    try:
        shutil.copyfile(probe, installed_probe)
        with tempfile.TemporaryDirectory() as working:
            for language in languages:
                probe_env = dict(env, QTWEBENGINEPROCESS_PATH=str(root / 'QtWebEngineProcess.exe'),
                                 QTWEBENGINE_RESOURCES_PATH=str(root / 'resources'),
                                 QTWEBENGINE_LOCALES_PATH=str(locales),
                                 QT_QPA_PLATFORM_PLUGIN_PATH=str(root / 'platforms'),
                                 QTWEBENGINE_CHROMIUM_FLAGS=f'--disable-gpu --lang={language}')
                run(installed_probe, cwd=working, env=probe_env)
    finally:
        installed_probe.unlink()
    return list(languages)


def verify(root, executable, revision, application_version, output, archive, signed=False, webengine_probe=None):
    root, executable = root.resolve(), executable.resolve()
    if not inside(executable, root):
        raise RuntimeError('Executable must be inside extracted package')
    archive_bytes = archive.stat().st_size
    env = clean_environment()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory() as working:
        result = subprocess.run([str(executable), '--core-self-test'], cwd=working, env=env,
                                check=True, capture_output=True, timeout=30)
    startup_ms = (time.perf_counter() - started) * 1000
    report = json.loads(result.stdout)
    arch = {'AMD64': 'amd64', 'x86_64': 'amd64', 'aarch64': 'arm64', 'ARM64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
    system = {'win32': 'windows', 'darwin': 'darwin', 'linux': 'linux'}[sys.platform]
    validate_report(report, revision, application_version, system, arch)
    report['proxy_recovery_worker'] = check_proxy_recovery(executable.parent, env)
    revisions = list(root.rglob('source-revision.txt'))
    if len(revisions) != 1 or revisions[0].read_text().strip() != revision:
        raise RuntimeError('Missing/mismatched packaged source revision')
    data = revisions[0].parent
    if 'CGO_ENABLED=1' not in (data / 'core-toolchain.txt').read_text():
        raise RuntimeError('Missing cgo toolchain evidence')
    for name in ('LICENSE', 'LICENSE.zju-connect', 'LICENSE.ping', 'UPSTREAM.md'):
        if not (data / 'licenses' / name).is_file():
            raise RuntimeError(f'Missing license/source notice: {name}')
    files = []
    for path in root.rglob('*'):
        if path.name.casefold() in ('zju-connect', 'zju-connect.exe', 'core-provenance', 'wintun.dll'):
            raise RuntimeError(f'Obsolete runtime in package: {path}')
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as stream:
                magic = stream.read(4)
            if magic == b'\x7fELF' or magic in (b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf') or magic[:2] == b'MZ':
                files.append(path)
    if system == 'windows':
        reader = executable.parent / 'JustConnectDnsReader.exe'
        report['dns_reader'] = check_windows_dns_reader(executable.parent, env)
        runtime = executable.parent / report['runtime']
        if runtime.parent != executable.parent or not runtime.is_file():
            raise RuntimeError('Runtime DLL must be next to the host')
        hidden = runtime.with_suffix('.hidden')
        runtime.rename(hidden)
        try:
            result = subprocess.run([str(executable), '--core-self-test'], env=env,
                                    capture_output=True, timeout=30)
            if result.returncode == 0:
                raise RuntimeError('Missing runtime unexpectedly succeeded')
        finally:
            hidden.rename(runtime)
        if webengine_probe is None:
            raise RuntimeError('Windows package verification requires the WebEngine probe')
        report['webengine_locales'] = check_windows_webengine(root, webengine_probe, env)
        report['audit'] = windows_audit(files, root, arch)
    elif report['runtime'] != 'static':
        raise RuntimeError('Unix packages must link the static core')
    elif system == 'darwin':
        report['audit'] = macos_audit(files, root, arch, env, signed)
    else:
        report['audit'] = linux_audit(files, root, arch, env)
    report['offline_self_test_wall_ms'] = startup_ms
    report['size_bytes'] = {
        'archive': archive_bytes,
        'installed': sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink()),
        'executable': executable.stat().st_size,
        'runtime_dll': runtime.stat().st_size if system == 'windows' else 0,
    }
    report['sha256'] = {}
    for path in [executable] + ([runtime, reader] if system == 'windows' else []):
        with path.open('rb') as stream:
            report['sha256'][str(path.relative_to(root))] = hashlib.file_digest(stream, 'sha256').hexdigest()
        if system == 'windows':
            status = windows_signature(path)
            if status not in ('Valid', 'NotSigned'):
                raise RuntimeError(f'Invalid Authenticode signature: {path}: {status}')
            report.setdefault('signatures', {})[path.name] = status
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'PASS: installed {system}/{arch}, ABI, source, lifecycle, {len(files)} native files; {output}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--signed', action='store_true')
    parser.add_argument('--webengine-probe', type=Path)
    args = parser.parse_args()
    verify(args.package, args.executable, args.revision, args.version, args.output, args.archive, args.signed, args.webengine_probe)
