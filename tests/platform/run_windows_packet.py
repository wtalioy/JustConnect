"""Verify Windows device ownership and the ordinary Qt/core packet path on disposable runners."""
import argparse
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]


def device():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Windows':
        raise RuntimeError('Native Windows network mutation requires a disposable runner')
    output = pathlib.Path('build/coreabi').resolve()
    sdk = output / 'wintun-probe'
    sdk.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('windows_helper_sdk', pathlib.Path('scripts/windows_helper_sdk.py').resolve())
    sdk_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sdk_module)
    contract = json.loads(sdk_module.CONTRACT.read_text(encoding='utf-8'))
    arch = {'X64': 'amd64', 'ARM64': 'arm64'}[os.environ['RUNNER_ARCH']]
    metadata = sdk_module.stage(contract, sdk, arch)
    dll = pathlib.Path(metadata['driver'])
    (output / 'windows-device-license.txt').write_bytes(pathlib.Path(metadata['license']).read_bytes())
    host = shutil.which('pwsh')
    if not host:
        raise RuntimeError('CI PowerShell host unavailable')
    env = dict(os.environ, JC_TEST_WINTUN_DLL=str(dll), CGO_ENABLED='0', GOTOOLCHAIN='local', GOWORK='off', GOENV='off')
    layout_host = output / 'windows-iphelper-layout.exe'
    subprocess.run([os.environ['CC'], '-std=c11', 'tests/platform/windows_iphelper_layout.c', '-o', str(layout_host)], check=True, timeout=60)
    layout = output / 'windows-iphelper-layout.json'
    layout.write_bytes(subprocess.check_output([str(layout_host)], timeout=10))
    env['JC_TEST_IPHELPER_LAYOUT'] = str(layout)
    with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as exported:
        exported.write('JC_TEST_IPHELPER_LAYOUT=' + str(layout) + '\n')
    subprocess.run(['go', '-C', 'corelib', 'test', '-mod=readonly', '-count=1', '-timeout=30s', './internal/tundevice/windows/wintun'], env=env, check=True, timeout=60)
    print('RUN: Wintun Authenticode via the CI pwsh host (60s)', flush=True)
    signature = json.loads(subprocess.check_output([host, '-NoProfile', '-NonInteractive', '-Command',
        '$s=Get-AuthenticodeSignature -LiteralPath $env:JC_TEST_WINTUN_DLL; $h=[System.Security.Cryptography.SHA256]::HashData($s.SignerCertificate.RawData); @{status=$s.Status.ToString(); signer=$s.SignerCertificate.Thumbprint; publisher=[Convert]::ToHexString($h).ToLowerInvariant()} | ConvertTo-Json -Compress'], env=env, text=True, timeout=60))
    if signature['status'] != 'Valid' or signature['signer'] != contract['sdk']['publisher_thumbprint']:
        raise RuntimeError(f'Untrusted Wintun signature: {signature}')
    metadata.update(signature=signature, powershell_host=host, source=os.environ['GITHUB_SHA'])
    env.update(JC_TEST_SIGNED_FIXTURE=str(dll), JC_TEST_PUBLISHER_SHA256=signature['publisher'])
    with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as exported:
        for key, value in {'JC_TEST_WINTUN_DLL': str(dll), 'JC_TEST_SIGNED_FIXTURE': str(dll), 'JC_TEST_PUBLISHER_SHA256': signature['publisher']}.items():
            exported.write(key + '=' + value + '\n')
    (output / 'windows-device.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    subprocess.run([os.sys.executable, 'tests/platform/run_windows_helper.py'], env=env, check=True, timeout=260)
    source = pathlib.Path('corelib/internal/tundevice/windows/wintun/fixture/main.go').resolve()
    tests = pathlib.Path('corelib/internal/tundevice/windows/wintun/fixture/main_test.go').resolve()
    if subprocess.check_output(['gofmt', '-l', str(source), str(tests)], env=env).strip():
        raise RuntimeError('Unformatted device probe')
    subprocess.run(['go', '-C', 'corelib', 'vet', str(source), str(tests)], env=env, check=True, timeout=120)
    probe, unit = output / 'windows-device-probe.exe', output / 'windows-device-unit.exe'
    subprocess.run(['go', '-C', 'corelib', 'build', '-mod=readonly', '-o', str(probe), str(source)], env=env, check=True, timeout=120)
    subprocess.run(['go', '-C', 'corelib', 'test', '-mod=readonly', '-c', '-o', str(unit), str(source), str(tests)], env=env, check=True, timeout=120)
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

    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device-only', action='store_true')
    args = parser.parse_args()
    os.chdir(ROOT)
    env = device()
    if args.device_only:
        return
    env.pop('CGO_ENABLED', None)
    subprocess.run(['go', '-C', 'corelib', 'test', '-mod=readonly', '-count=1', '-timeout=30s', './internal/packetpipe'], env=env, check=True, timeout=60)
    output = ROOT / 'build/coreabi'
    subprocess.run(['cmake', '-S', 'tests/coreabi', '-B', str(output), '-DCMAKE_BUILD_TYPE=Release', '-A',
        'ARM64' if os.environ['RUNNER_ARCH'] == 'ARM64' else 'x64'], check=True, timeout=120)
    subprocess.run(['cmake', '--build', str(output), '--config', 'Release', '--target', 'coreabi_windows_packet_test', '--parallel', '3'], check=True, timeout=600)
    subprocess.run(['ctest', '--test-dir', str(output), '-C', 'Release', '-V', '-R', '^coreabi_windows_packet_test$', '--output-on-failure'], env=env, check=True, timeout=150)


if __name__ == '__main__':
    main()
