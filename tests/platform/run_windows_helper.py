"""Validate protected Windows helper payloads on an ephemeral, elevated runner."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Windows':
        raise RuntimeError('Machine installation checks require a disposable Windows runner')
    os.chdir(ROOT)
    output = ROOT / 'build/coreabi'
    metadata = json.loads((output / 'windows-device.json').read_text(encoding='utf-8'))
    contract = json.loads((ROOT / 'resource/network-helper-windows.json').read_text(encoding='utf-8'))
    destination = Path(metadata['driver']).parent
    host = metadata['powershell_host']
    script = r'''
$ErrorActionPreference = 'Stop'
$certificate = $null
$trusted = $false
$ownedService = $false
$ownedDirectory = $null
try {
    Write-Host 'RUN: create ephemeral signing key'
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=JustConnect ephemeral helper validation" -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    Write-Host 'RUN: trust ephemeral signing certificate'
    $root = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
    $root.Open('ReadWrite')
    try { $root.Add($certificate); $trusted = $true } finally { $root.Close() }
    $publisher = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($certificate.RawData)).ToLowerInvariant()
    Write-Host 'RUN: configure native C++ installation authority'
    & cmake -S tests/platform/windows_device -B $env:JC_HELPER_NATIVE_BUILD '-DCMAKE_BUILD_TYPE=Release' "-DWINTUN_INCLUDE_DIR=$env:JC_HELPER_SDK_DIRECTORY" -A $env:JC_HELPER_CMAKE_ARCH "-DJC_HELPER_PUBLISHER_SHA256=$publisher" "-DJC_HELPER_DRIVER_SHA256=$env:JC_HELPER_DRIVER_SHA256" "-DJC_HELPER_LICENSE_SHA256=$env:JC_HELPER_LICENSE_SHA256"
    if ($LASTEXITCODE -ne 0) { throw 'Native helper configuration failed' }
    & cmake --build $env:JC_HELPER_NATIVE_BUILD --config Release --target windows_installation_test windows_helper windows_recovery_test --parallel 3
    if ($LASTEXITCODE -ne 0) { throw 'Native helper installation build failed' }
    Copy-Item -LiteralPath (Join-Path $env:JC_HELPER_NATIVE_BUILD 'Release/windows_installation_test.exe') -Destination $env:JC_HELPER_TEST_IMAGE
    $nativeSignature = Set-AuthenticodeSignature -LiteralPath $env:JC_HELPER_TEST_IMAGE -Certificate $certificate -HashAlgorithm SHA256
    if ($nativeSignature.Status -ne 'Valid') { throw "Native installation image signature: $($nativeSignature.Status)" }
    Write-Host 'RUN: signed C++ installation and ordinary-user boundaries'
    & $env:JC_HELPER_TEST_IMAGE
    if ($LASTEXITCODE -ne 0) { throw 'Signed native C++ installation failed' }
    if (Get-Service -Name $env:JC_HELPER_SERVICE_NAME -ErrorAction SilentlyContinue) { throw 'Refuse pre-existing recovery service in fixture' }
    Copy-Item -LiteralPath (Join-Path $env:JC_HELPER_NATIVE_BUILD "Release/$env:JC_HELPER_EXECUTABLE") -Destination $env:JC_HELPER_SERVICE_IMAGE
    $signature = Set-AuthenticodeSignature -LiteralPath $env:JC_HELPER_SERVICE_IMAGE -Certificate $certificate -HashAlgorithm SHA256
    if ($signature.Status -ne 'Valid') { throw 'Recovery service fixture signature failed' }
    $hash = (Get-FileHash -LiteralPath $env:JC_HELPER_SERVICE_IMAGE -Algorithm SHA256).Hash.ToLowerInvariant()
    $directory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) (Join-Path $env:JC_HELPER_INSTALL_DIRECTORY $hash)
    if (Test-Path -LiteralPath $directory) { throw 'Refuse pre-existing service payload directory in fixture' }
    $ownedDirectory = $directory
    $ownedService = $true
    Write-Host 'RUN: signed production C++ service install and idempotent reuse'
    $installed = & $env:JC_HELPER_SERVICE_IMAGE --install
    if ($LASTEXITCODE -ne 0 -or $installed -isnot [string]) { throw 'Recovery service installation failed' }
    $reused = & $env:JC_HELPER_SERVICE_IMAGE --install
    if ($LASTEXITCODE -ne 0 -or $reused -ne $installed) { throw 'Recovery service reuse changed its identity' }
    Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$($certificate.Thumbprint)" -Force
    $trusted = $false
    Write-Host 'RUN: actual SCM restart, independent owned recovery and ordinary-user control denial without installer trust'
    & (Join-Path $env:JC_HELPER_NATIVE_BUILD 'Release/windows_recovery_test.exe') --service (Join-Path $directory $env:JC_HELPER_DRIVER_NAME)
    if ($LASTEXITCODE -ne 0) { throw 'Independent SCM recovery failed' }
} finally {
    try {
        if ($ownedService -and (Get-Service -Name $env:JC_HELPER_SERVICE_NAME -ErrorAction SilentlyContinue)) {
            Stop-Service -Name $env:JC_HELPER_SERVICE_NAME
            & sc.exe delete $env:JC_HELPER_SERVICE_NAME
            if ($LASTEXITCODE -ne 0) { throw 'Fixture service cleanup failed' }
        }
        if ($null -ne $ownedDirectory -and (Test-Path -LiteralPath $ownedDirectory)) { Remove-Item -LiteralPath $ownedDirectory -Recurse -Force }
    } finally {
        if ($trusted) { Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$($certificate.Thumbprint)" -Force }
        if ($null -ne $certificate) { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -DeleteKey }
    }
}
'''
    env = dict(os.environ,
               JC_HELPER_DRIVER_SHA256=metadata['driver_sha256'],
               JC_HELPER_LICENSE_SHA256=metadata['license_sha256'],
               JC_HELPER_NATIVE_BUILD=metadata['native_build'],
               JC_HELPER_SDK_DIRECTORY=str(destination),
               JC_HELPER_CMAKE_ARCH='ARM64' if metadata['arch'] == 'arm64' else 'x64',
               JC_HELPER_TEST_IMAGE=str(destination / 'helper-validation.exe'),
               JC_HELPER_SERVICE_IMAGE=str(destination / contract['executable']),
               JC_HELPER_SERVICE_NAME=contract['service'], JC_HELPER_DRIVER_NAME=contract['driver_library'],
               JC_HELPER_EXECUTABLE=contract['executable'], JC_HELPER_INSTALL_DIRECTORY=contract['install_directory'])
    script_path = output / 'validate-windows-helper.ps1'
    script_path.write_text(script, encoding='utf-8')
    log_path = output / 'windows-helper.log'
    with log_path.open('w', encoding='utf-8') as log:
        try:
            result = subprocess.run([host, '-NoProfile', '-NonInteractive', '-File', str(script_path)], env=env,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=240)
            if result.returncode:
                raise RuntimeError(f'Protected Windows helper check failed: {result.returncode}')
        finally:
            log.flush()
            print(log_path.read_text(encoding='utf-8', errors='replace'), flush=True)


if __name__ == '__main__':
    main()
