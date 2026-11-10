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
WINDOWS_HELPER = json.loads((ROOT / 'resource/network-helper-windows.json').read_text())
PROXY_RECOVERY_PROTOCOL = int(re.search(
    r'\bProxyRecoveryProtocol\s*=\s*(\d+)\s*;',
    (ROOT / 'infrastructure/systemproxy/proxyrecovery.h').read_text()).group(1))


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
    if (not isinstance(facts, dict) or set(facts) != {'interfaces', 'clients', 'global', 'nrpt', 'nrpt_sources', 'doh_supported', 'doh', 'adapters', 'native_global', 'configured_encryption'}
            or any(not isinstance(facts[key], list) for key in ('interfaces', 'clients', 'nrpt', 'nrpt_sources', 'doh', 'adapters', 'configured_encryption'))
            or not isinstance(facts['global'], dict) or not isinstance(facts['doh_supported'], bool)
            or not isinstance(facts['native_global'], dict)
            or type(facts['native_global'].get('Status')) is not int
            or 'Value' not in facts['native_global']
            or (facts['native_global']['Status'] == 0 and not isinstance(facts['native_global']['Value'], dict))
            or (facts['native_global']['Status'] != 0 and facts['native_global']['Value'] is not None)):
        raise RuntimeError('Packaged DNS reader did not return complete native facts')
    return {'interfaces': len(facts['interfaces']), 'effective_nrpt': len(facts['nrpt']), 'native_adapters': len(facts['adapters'])}


def check_proxy_recovery(root, env):
    worker = root / ('JustConnectProxyRecovery.exe' if sys.platform == 'win32' else 'JustConnectProxyRecovery')
    if not worker.is_file():
        raise RuntimeError('Missing packaged system proxy recovery worker')
    facts = json.loads(run(worker, '--version', env=env, timeout=5))
    if (not isinstance(facts, dict) or set(facts) != {'worker', 'protocol', 'qt'} or facts['worker'] != 'system-proxy-recovery'
            or type(facts['protocol']) is not int or facts['protocol'] != PROXY_RECOVERY_PROTOCOL
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


def macos_signature(path, env):
    return subprocess.run(['codesign', '-dv', '--verbose=4', str(path)], env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stderr.decode('utf-8')


def macos_audit(files, root, arch, env):
    evidence, minimum = [], '0'
    for path in files:
        if path.parent != root / 'Contents/MacOS':
            raise RuntimeError(f'Unexpected packaged macOS code outside the executable directory: {path}')
        expected = 'arm64' if arch == 'arm64' else 'x86_64'
        if run('lipo', '-archs', path, env=env).strip() != expected:
            raise RuntimeError(f'Wrong Mach-O architecture: {path}')
        commands = run('otool', '-l', path, env=env)
        for rpath in re.findall(r'\bpath (.*?) \(offset', commands):
            if rpath.startswith('/') and not rpath.startswith(('/System/Library/', '/usr/lib/')):
                raise RuntimeError(f'Non-relocatable Mach-O search path: {path}: {rpath}')
        for block in commands.split('Load command '):
            if re.search(r'cmd LC_(BUILD_VERSION|VERSION_MIN_MACOSX)\b', block):
                match = re.search(r'^\s+(?:minos|version)\s+([0-9.]+)', block, re.M)
                if match and version(match[1]) > version(minimum):
                    minimum = match[1]
        dependencies = run('otool', '-L', path, env=env)
        for line in dependencies.splitlines()[1:]:
            dependency = line.strip().split(' (', 1)[0]
            if not dependency.startswith(('/System/Library/', '/usr/lib/')):
                raise RuntimeError(f'Packaged macOS executable links a non-system dynamic library: {path}: {dependency}')
        signing_flags = re.search(r'\bflags=0x([0-9a-f]+)', macos_signature(path, env))
        required_flags = 0x10000 | 0x2000  # CS_RUNTIME | CS_REQUIRE_LV
        if not signing_flags or (int(signing_flags[1], 16) & required_flags) != required_flags:
            raise RuntimeError(f'Packaged macOS executable lacks hardened runtime or library validation: {path}')
        evidence.append({'file': str(path.relative_to(root)), 'dependencies': dependencies})
    info = plistlib.loads((root / 'Contents/Info.plist').read_bytes())
    for key, pattern in (('CFBundleVersion', r'[0-9]+(?:\.[0-9]+){0,2}'),
                         ('CFBundleShortVersionString', r'[0-9]+(?:\.[0-9]+){2}')):
        value = info.get(key)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise RuntimeError(f'Invalid macOS bundle version: {key}')
    declared = info['LSMinimumSystemVersion']
    host_macos = platform.mac_ver()[0]
    if version(minimum) > version(declared) or version(declared) > version(host_macos):
        raise RuntimeError(f'Invalid macOS floor: declared {declared}, binaries {minimum}')
    source_icon = ROOT / 'resource/JustConnect.icns'
    installed_icon = root / 'Contents/Resources' / source_icon.name
    if (info.get('CFBundleIconFile') != source_icon.name or not installed_icon.is_file()
            or installed_icon.read_bytes() != source_icon.read_bytes()):
        raise RuntimeError('Packaged macOS app icon is missing or differs from its bundle declaration')
    run('codesign', '--verify', '--deep', '--strict', root, env=env)
    signature = macos_signature(root, env)
    if 'Identifier=' + info['CFBundleIdentifier'] not in signature.splitlines():
        raise RuntimeError('Application signing identifier differs from its bundle')
    return {'host_macos': host_macos, 'minimum_macos': declared, 'binary_minimum': minimum,
            'icon': source_icon.name, 'signature': signature, 'files': evidence,
            'network_helper': check_macos_network_helper(root, env)}


def check_macos_network_helper(root, env):
    layout = json.loads((ROOT / 'resource/network-helper-macos.json').read_text())
    identifier = plistlib.loads((root / 'Contents/Info.plist').read_bytes())['CFBundleIdentifier'] + layout['service_suffix']
    helper = root / 'Contents/MacOS' / layout['executable']
    launch = plistlib.loads((root / 'Contents/Library/LaunchDaemons' / (identifier + '.plist')).read_bytes())
    if launch != {'Label': identifier, 'BundleProgram': 'Contents/MacOS/' + layout['executable'], 'MachServices': {identifier: True},
                  'UserName': 'root', 'RunAtLoad': True, 'ThrottleInterval': 2,
                  'KeepAlive': {'SuccessfulExit': False}, 'ProcessType': 'Adaptive'}:
        raise RuntimeError('Packaged network daemon expands its fixed privilege contract')
    facts = json.loads(run(helper, '--version', env=env, timeout=10))
    if (not isinstance(facts, dict) or set(facts) != {'protocol', 'storage_version', 'revision', 'source_state', 'identity_ready'}
            or type(facts['protocol']) is not int or type(facts['storage_version']) is not int or type(facts['identity_ready']) is not bool
            or facts['protocol'] != layout['protocol'] or facts['storage_version'] != layout['storage_version']
            or facts['revision'] != (root / 'Contents/Resources/source-revision.txt').read_text().strip()
            or facts['source_state'] != 'clean' or not facts['identity_ready']):
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


def check_windows_network_helper(root, env, revision):
    helper = root / WINDOWS_HELPER['executable']
    if not helper.is_file():
        raise RuntimeError('Missing packaged Windows network helper')
    facts = json.loads(run(helper, '--version', env=env, timeout=10))
    if (not isinstance(facts, dict) or set(facts) != {'protocol', 'storage_version', 'revision', 'source_state',
                                                                  'identity_ready', 'driver_sha256', 'license_sha256'}
            or type(facts['protocol']) is not int or facts['protocol'] != WINDOWS_HELPER['protocol']
            or type(facts['storage_version']) is not int or facts['storage_version'] != WINDOWS_HELPER['storage_version']
            or facts['revision'] != revision or facts['source_state'] != 'clean'
            or facts['identity_ready'] is not True):
        raise RuntimeError('Packaged Windows network helper has mismatched provenance or payload configuration')
    for field, name in [('driver_sha256', 'driver_library'), ('license_sha256', 'driver_license')]:
        payload = root / WINDOWS_HELPER[name]
        if not payload.is_file() or hashlib.sha256(payload.read_bytes()).hexdigest() != facts[field]:
            raise RuntimeError('Packaged Windows network helper payload hash mismatch: ' + name)
    signature = windows_signature(helper)
    if signature not in ('Valid', 'NotSigned'):
        raise RuntimeError('Packaged Windows network helper signature is invalid')
    if windows_signature(root / WINDOWS_HELPER['driver_library']) != 'Valid':
        raise RuntimeError('Packaged Windows native driver signature is invalid')
    imports = run('llvm-readobj', '--coff-imports', helper)
    if re.search(r'Name:\s+(?:Qt6|justconnect_core)', imports, re.I):
        raise RuntimeError('Privileged Windows network helper links application/data-plane libraries')
    return dict(facts, signature=signature)


def check_signin_browser(root, executable, probe, env):
    if probe is None:
        raise RuntimeError('Package verification requires the native sign-in browser probe')
    with tempfile.TemporaryDirectory() as working:
        directory = executable.parent if sys.platform == 'win32' else Path(working)
        descriptor, name = tempfile.mkstemp(prefix='signin-browser-check-', suffix=executable.suffix, dir=directory)
        os.close(descriptor)
        installed_probe = Path(name)
        try:
            shutil.copyfile(probe, installed_probe)
            installed_probe.chmod(0o755)
            probe_env = dict(env, QT_QPA_PLATFORM='windows' if sys.platform == 'win32' else 'cocoa')
            if sys.platform == 'win32':
                probe_env['QT_QPA_PLATFORM_PLUGIN_PATH'] = str(root / 'platforms')
            run(installed_probe, cwd=working, env=probe_env, timeout=30)
        finally:
            installed_probe.unlink()
    return 'WebView2' if sys.platform == 'win32' else 'WKWebView'


def verify(root, executable, revision, application_version, output, archive, browser_probe=None):
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
    system = {'win32': 'windows', 'darwin': 'darwin'}[sys.platform]
    validate_report(report, revision, application_version, system, arch)
    report['proxy_recovery_worker'] = check_proxy_recovery(executable.parent, env)
    revisions = list(root.rglob('source-revision.txt'))
    if len(revisions) != 1 or revisions[0].read_text().strip() != revision:
        raise RuntimeError('Missing/mismatched packaged source revision')
    data = revisions[0].parent
    if 'CGO_ENABLED=1' not in (data / 'core-toolchain.txt').read_text():
        raise RuntimeError('Missing cgo toolchain evidence')
    for name in ('LICENSE', 'LICENSE.zju-connect', 'LICENSE.ping', 'LICENSE.lucide', 'UPSTREAM.md'):
        if not (data / 'licenses' / name).is_file():
            raise RuntimeError(f'Missing license/source notice: {name}')
    if system == 'windows' and not (data / 'licenses/LICENSE.WebView2').is_file():
        raise RuntimeError('Missing WebView2 loader license')
    files = []
    for path in root.rglob('*'):
        if system == 'windows' and path.name.casefold() == 'qtuiotouchplugin.dll':
            raise RuntimeError(f'Unused TUIO plugin in package: {path}')
        if 'webengine' in path.name.casefold() or path.name.casefold() == 'icudtl.dat':
            raise RuntimeError(f'Obsolete bundled browser in package: {path}')
        if (path.name.casefold() in ('zju-connect', 'zju-connect.exe', 'core-provenance')
                or (path.name.casefold() == WINDOWS_HELPER['driver_library'].casefold()
                    and not (system == 'windows' and path == executable.parent / WINDOWS_HELPER['driver_library']))):
            raise RuntimeError(f'Obsolete runtime in package: {path}')
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as stream:
                magic = stream.read(4)
            if magic in (b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf') or magic[:2] == b'MZ':
                files.append(path)
    if system == 'windows':
        report['network_helper'] = check_windows_network_helper(executable.parent, env, revision)
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
        report['audit'] = windows_audit(files, root, arch)
    elif report['runtime'] != 'static':
        raise RuntimeError('macOS packages must link the static core')
    else:
        report['audit'] = macos_audit(files, root, arch, env)
    report['sign_in_browser'] = check_signin_browser(root, executable, browser_probe, env)
    report['offline_self_test_wall_ms'] = startup_ms
    installed_files = [
        {'path': str(path.relative_to(root)), 'bytes': path.stat().st_size}
        for path in root.rglob('*') if path.is_file() and not path.is_symlink()
    ]
    report['size_bytes'] = {
        'archive': archive_bytes,
        'installed': sum(item['bytes'] for item in installed_files),
        'executable': executable.stat().st_size,
        'runtime_dll': runtime.stat().st_size if system == 'windows' else 0,
    }
    with archive.open('rb') as stream:
        report['archive_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    report['largest_files'] = sorted(installed_files, key=lambda item: item['bytes'], reverse=True)[:15]
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
    parser.add_argument('--browser-probe', type=Path)
    args = parser.parse_args()
    verify(args.package, args.executable, args.revision, args.version, args.output, args.archive, args.browser_probe)
