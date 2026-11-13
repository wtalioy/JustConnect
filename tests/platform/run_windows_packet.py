"""Stage and verify the native Windows backends on disposable runners."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess

from windows_system_dns import verify as verify_system_dns

ROOT = pathlib.Path(__file__).resolve().parents[2]


def stage_sdk(output, *, prepared=False):
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Windows':
        raise RuntimeError('Native Windows network mutation requires a disposable runner')
    sdk = output / 'wintun-probe'
    spec = importlib.util.spec_from_file_location('windows_helper_sdk', ROOT / 'scripts/windows_helper_sdk.py')
    sdk_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sdk_module)
    contract = json.loads(sdk_module.CONTRACT.read_text(encoding='utf-8'))
    arch = {'X64': 'amd64', 'ARM64': 'arm64'}[os.environ['RUNNER_ARCH']]
    native = output / 'windows-device'
    if prepared:
        metadata = json.loads((output / 'windows-device.json').read_text(encoding='utf-8'))
        if (metadata.get('source') != os.environ['GITHUB_SHA'] or metadata.get('arch') != arch
                or metadata.get('archive_sha256') != contract['sdk']['archive_sha256']
                or pathlib.Path(metadata['native_build']) != native):
            raise RuntimeError('Staged Windows SDK does not belong to this build')
        for key, filename in (('driver', contract['driver_library']), ('license', contract['driver_license']),
                              ('header', contract['sdk']['header_file'])):
            path = sdk / filename
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if pathlib.Path(metadata[key]) != path or digest != metadata[f'{key}_sha256']:
                raise RuntimeError(f'Staged Windows SDK {key} differs from the verified archive')
        return contract, arch, metadata
    metadata = sdk_module.stage(contract, sdk, arch)
    metadata['native_build'] = str(native)
    return contract, arch, metadata


def build_native(native, target):
    subprocess.run(['cmake', '--build', str(native), '--config', 'Release', '--parallel', '3',
                    '--target', target], check=True, timeout=180)
    return native / 'Release'


def verify_native_dns(native, output, arch):
    subprocess.run([str(native / 'windows_dnsreader_test.exe'), '--self-test'], check=True, timeout=10)
    spec = importlib.util.spec_from_file_location('verify_package', ROOT / 'scripts/verify-package.py')
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    report = package.check_windows_dns_reader(native, dict(os.environ))
    report.update(source=os.environ['GITHUB_SHA'], arch=arch)
    (output / 'windows-native-dns.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('PASS: native DNS reader and source facts verified before Qt/Go setup', flush=True)


def device():
    output = pathlib.Path('build/coreabi').resolve()
    contract, arch, metadata = stage_sdk(output, prepared=True)
    dll = pathlib.Path(metadata['driver'])
    (output / 'windows-device-license.txt').write_bytes(pathlib.Path(metadata['license']).read_bytes())
    host = shutil.which('pwsh')
    if not host:
        raise RuntimeError('CI PowerShell host unavailable')
    env = dict(os.environ, JC_TEST_WINTUN_DLL=str(dll), CGO_ENABLED='0', GOTOOLCHAIN='local', GOWORK='off', GOENV='off')
    print('RUN: Wintun Authenticode via the CI pwsh host (60s)', flush=True)
    signature = json.loads(subprocess.check_output([host, '-NoProfile', '-NonInteractive', '-Command',
        '$s=Get-AuthenticodeSignature -LiteralPath $env:JC_TEST_WINTUN_DLL; $h=[System.Security.Cryptography.SHA256]::HashData($s.SignerCertificate.RawData); @{status=$s.Status.ToString(); signer=$s.SignerCertificate.Thumbprint; publisher=[Convert]::ToHexString($h).ToLowerInvariant()} | ConvertTo-Json -Compress'], env=env, text=True, timeout=60))
    if signature['status'] != 'Valid' or signature['signer'] != contract['sdk']['publisher_thumbprint']:
        raise RuntimeError(f'Untrusted Wintun signature: {signature}')
    metadata.update(signature=signature, powershell_host=host, source=os.environ['GITHUB_SHA'])
    with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as exported:
        exported.write('JC_TEST_WINTUN_DLL=' + str(dll) + '\n')
    (output / 'windows-device.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    # The preceding helper checks configured this build with verified SDK inputs.
    native = build_native(pathlib.Path(metadata['native_build']), 'windows_device_checks')
    subprocess.run([str(native / 'windows_device_concurrency_test.exe')], check=True, timeout=15)
    subprocess.run([str(native / 'windows_device_removal_test.exe')], check=True, timeout=15)
    subprocess.run([str(native / 'windows_device_reuse_test.exe'), str(dll)], env=env, check=True, timeout=30)
    subprocess.run([str(native / 'windows_session_wakeup_test.exe'), str(dll)], env=env, check=True, timeout=30)
    subprocess.run([str(native / 'windows_process_identity_test.exe')], check=True, timeout=15)
    subprocess.run([str(native / 'windows_registry_journal_test.exe')], env=env, check=True, timeout=30)
    subprocess.run([str(native / 'windows_packet_frame_test.exe')], env=env, check=True, timeout=15)
    subprocess.run([str(native / 'windows_nrpt_test.exe')], env=env, check=True, timeout=30)
    env['JC_TEST_CPP_WINTUN_BROKER'] = str(native / 'windows_device_broker.exe')
    trap = output / 'windows-device-loader-trap'
    trap.mkdir(exist_ok=True)
    guarded = trap / 'windows_device_broker.exe'
    shutil.copy2(env['JC_TEST_CPP_WINTUN_BROKER'], guarded)
    (trap / 'iphlpapi.dll').write_bytes(b'not a DLL: adjacent dependency must never be loaded')
    checked = subprocess.run([str(guarded)], env=env, capture_output=True, text=True, timeout=15)
    if checked.returncode != 1 or 'device fixture requires' not in checked.stderr:
        raise RuntimeError(f'Native broker loaded an adjacent dependency: {checked.returncode}: {checked.stderr}')
    print('PASS: native broker resolves system dependencies before main and refuses unguarded device execution', flush=True)

    with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as exported:
        exported.write('JC_TEST_CPP_WINTUN_BROKER=' + env['JC_TEST_CPP_WINTUN_BROKER'] + '\n')
    package = './tests/windows/device'
    if subprocess.check_output(['gofmt', '-l', 'corelib/tests/windows/device'], env=env).strip():
        raise RuntimeError('Unformatted device probe')
    probe, unit = output / 'windows-device-probe.exe', output / 'windows-device-unit.exe'
    flags = ['-mod=readonly', '-tags=jc_wintun_probe']
    subprocess.run(['go', '-C', 'corelib', 'build', *flags, '-o', str(probe), package], env=env, check=True, timeout=120)
    subprocess.run(['go', '-C', 'corelib', 'test', *flags, '-vet=all', '-c', '-o', str(unit), package], env=env, check=True, timeout=120)
    log_path = output / 'windows-device.log'
    with log_path.open('w', encoding='utf-8') as log:
        try:
            for args in ([str(unit), '-test.v'], [str(probe), str(dll)]):
                result = subprocess.run(args, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
                if result.returncode:
                    raise RuntimeError(f'Device probe failed: {result.returncode}')
        finally:
            log.flush()
            print(log_path.read_text(encoding='utf-8', errors='replace'), flush=True)

    benchmark_log = output / 'windows-device-benchmark.log'
    count = 4096
    measured = dict(env, JC_TEST_WINTUN_BENCHMARK_PACKETS=str(count), JC_TEST_WINTUN_BENCHMARK_TIMEOUT_MS='30000')
    with benchmark_log.open('w', encoding='utf-8') as log:
        try:
            result = subprocess.run([str(probe), '--benchmark', str(dll)], env=measured, stdout=log, stderr=subprocess.STDOUT, timeout=100)
            if result.returncode:
                raise RuntimeError(f'Native device batch failed: {result.returncode}')
        finally:
            log.flush()
            print(benchmark_log.read_text(encoding='utf-8', errors='replace'), flush=True)
    records = [json.loads(line) for line in benchmark_log.read_text(encoding='utf-8').splitlines() if line.startswith('{')]
    expected = {(kind, 'cpp') for kind in ('helper', 'client')}
    if len(records) != len(expected) or {(r.get('benchmark'), r.get('backend')) for r in records} != expected:
        raise RuntimeError('Native device batch omitted the helper or ordinary client')
    for record in records:
        if record['round_trips'] != count:
            raise RuntimeError('Native device comparison did not exchange all packets')
        if record['benchmark'] == 'helper' and (record['seconds'] <= 0 or record['peak_rss_bytes'] <= 0 or record['cpu_seconds'] < 0):
            raise RuntimeError('Invalid native device measurements')
        if record['benchmark'] == 'client' and not 0 < record['p50_us'] <= record['p95_us'] <= record['p99_us']:
            raise RuntimeError('Invalid native latency counter measurements')
    (output / 'windows-device-benchmark.json').write_text(json.dumps({
        'source': os.environ['GITHUB_SHA'], 'arch': arch, 'driver_sha256': metadata['driver_sha256'],
        'scenario': '4096 ordinary-client 4-byte UDP round trips over real Wintun and framed IPC; not campus or full Qt throughput',
        'measurements': records,
    }, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--device-only', action='store_true', help='Run the device probe with the inputs from --build-only')
    mode.add_argument('--build-only', action='store_true', help='Build and check native Windows DNS and recovery before installing Qt/Go')
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.build_only:
        output = pathlib.Path('build/coreabi').resolve()
        _, arch, metadata = stage_sdk(output)
        build = pathlib.Path(metadata['native_build'])
        subprocess.run(['cmake', '-S', 'tests/platform/windows_device', '-B', str(build),
            '-DCMAKE_BUILD_TYPE=Release', '-DWINTUN_INCLUDE_DIR=' + str(pathlib.Path(metadata['header']).parent),
            '-A', 'ARM64' if arch == 'arm64' else 'x64'], check=True, timeout=120)
        native = build_native(build, 'windows_initial_checks')
        verify_native_dns(native, output, arch)
        subprocess.run([str(native / 'windows_session_test.exe')], check=True, timeout=15)
        subprocess.run([str(native / 'windows_installation_test.exe'), '--unconfigured'], check=True, timeout=15)
        verify_system_dns(native / 'windows_system_dns_test.exe')
        subprocess.run([str(native / 'windows_recovery_test.exe'), metadata['driver']], check=True, timeout=120)
        metadata.update(powershell_host=shutil.which('pwsh'), source=os.environ['GITHUB_SHA'])
        if not metadata['powershell_host']:
            raise RuntimeError('Native helper validation requires the CI PowerShell host')
        (output / 'windows-device.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
        subprocess.run([os.sys.executable, 'tests/platform/run_windows_helper.py'], check=True, timeout=260)
        return
    device()


if __name__ == '__main__':
    main()
