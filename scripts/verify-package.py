"""Run the installed application's offline ABI check and audit native dependencies."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args, env=None):
    result = subprocess.run(list(map(str, args)), env=env, check=False,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: '
                           + result.stderr.decode('utf-8', errors='replace')
                           + result.stdout.decode('utf-8', errors='replace'))
    return result.stdout.decode('utf-8', errors='replace')


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
    signature = subprocess.run(['codesign', '-dv', '--verbose=4', str(root)], env=env, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE).stderr.decode('utf-8')
    if signed and ('Signature=adhoc' in signature or 'Authority=Developer ID Application:' not in signature):
        raise RuntimeError('Developer ID signature required')
    return {'minimum_macos': declared, 'binary_minimum': minimum, 'signature': signature, 'files': evidence}


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


def verify(root, executable, revision, application_version, output, signed=False):
    root, executable = root.resolve(), executable.resolve()
    if not inside(executable, root):
        raise RuntimeError('Executable must be inside extracted package')
    env = clean_environment()
    with tempfile.TemporaryDirectory() as working:
        result = subprocess.run([str(executable), '--core-self-test'], cwd=working, env=env,
                                check=True, capture_output=True, timeout=30)
    report = json.loads(result.stdout)
    arch = {'AMD64': 'amd64', 'x86_64': 'amd64', 'aarch64': 'arm64', 'ARM64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
    system = {'win32': 'windows', 'darwin': 'darwin', 'linux': 'linux'}[sys.platform]
    validate_report(report, revision, application_version, system, arch)
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
        raise RuntimeError('Unix packages must link the static core')
    elif system == 'darwin':
        report['audit'] = macos_audit(files, root, arch, env, signed)
    else:
        report['audit'] = linux_audit(files, root, arch, env)
    report['sha256'] = {}
    for path in [executable] + ([runtime] if system == 'windows' else []):
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
    parser.add_argument('--signed', action='store_true')
    args = parser.parse_args()
    verify(args.package, args.executable, args.revision, args.version, args.output, args.signed)
