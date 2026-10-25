"""Validate protected Windows helper payloads on an ephemeral, elevated runner."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qt-control", action="store_true")
    parser.add_argument("--session-host", type=Path)
    args = parser.parse_args()
    if args.session_host and not args.session_host.is_absolute():
        parser.error('--session-host requires the absolute built application fixture path')
    args.qt_control = args.qt_control or bool(args.session_host)
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
$qtOnly = $env:JC_HELPER_QT_CONTROL -eq 'true'
$qtOption = if ($qtOnly) { 'ON' } else { 'OFF' }
try {
    Write-Host 'RUN: create ephemeral signing key'
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=JustConnect ephemeral helper validation" -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    Write-Host 'RUN: trust ephemeral signing certificate'
    $root = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
    $root.Open('ReadWrite')
    try { $root.Add($certificate); $trusted = $true } finally { $root.Close() }
    $publisher = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($certificate.RawData)).ToLowerInvariant()
    Write-Host 'RUN: configure native C++ installation authority'
    & cmake -S tests/platform/windows_device -B $env:JC_HELPER_NATIVE_BUILD '-DCMAKE_BUILD_TYPE=Release' "-DWINTUN_INCLUDE_DIR=$env:JC_HELPER_SDK_DIRECTORY" -A $env:JC_HELPER_CMAKE_ARCH "-DJC_HELPER_PUBLISHER_SHA256=$publisher" "-DJC_HELPER_DRIVER_SHA256=$env:JC_HELPER_DRIVER_SHA256" "-DJC_HELPER_LICENSE_SHA256=$env:JC_HELPER_LICENSE_SHA256" "-DJC_WINDOWS_QT_CONTROL_TEST=$qtOption"
    if ($LASTEXITCODE -ne 0) { throw 'Native helper configuration failed' }
    & cmake --build $env:JC_HELPER_NATIVE_BUILD --config Release --target windows_installation_test windows_helper windows_recovery_test windows_control_test --parallel 3
    if ($LASTEXITCODE -ne 0) { throw 'Native helper installation build failed' }
    if ($qtOnly -and -not $env:JC_HELPER_QT_SESSION_HOST) {
        & cmake --build $env:JC_HELPER_NATIVE_BUILD --config Release --target windows_control_qt_test --parallel 3
        if ($LASTEXITCODE -ne 0) { throw 'Ordinary Qt control build failed' }
    }
    Copy-Item -LiteralPath (Join-Path $env:JC_HELPER_NATIVE_BUILD 'Release/windows_control_test.exe') -Destination $env:JC_HELPER_CONTROL_IMAGE
    $controlSignature = Set-AuthenticodeSignature -LiteralPath $env:JC_HELPER_CONTROL_IMAGE -Certificate $certificate -HashAlgorithm SHA256
    if ($controlSignature.Status -ne 'Valid') { throw 'Control fixture signature failed' }
    if (-not $qtOnly) {
        Copy-Item -LiteralPath (Join-Path $env:JC_HELPER_NATIVE_BUILD 'Release/windows_installation_test.exe') -Destination $env:JC_HELPER_TEST_IMAGE
        $nativeSignature = Set-AuthenticodeSignature -LiteralPath $env:JC_HELPER_TEST_IMAGE -Certificate $certificate -HashAlgorithm SHA256
        if ($nativeSignature.Status -ne 'Valid') { throw "Native installation image signature: $($nativeSignature.Status)" }
        Write-Host 'RUN: signed C++ installation and ordinary-user boundaries'
        & $env:JC_HELPER_TEST_IMAGE
        if ($LASTEXITCODE -ne 0) { throw 'Signed native C++ installation failed' }
    }
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
    if (-not $qtOnly) {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$env:JC_HELPER_SERVICE_NAME'"
        $originalCommand = $service.PathName
        $foreignCommand = "$originalCommand --unowned"
        $changed = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{PathName=$foreignCommand}
        if ($changed.ReturnValue -ne 0) { throw 'Could not prepare foreign service configuration fixture' }
        try {
            & $env:JC_HELPER_SERVICE_IMAGE --install
            if ($LASTEXITCODE -eq 0) { throw 'Installer adopted foreign service configuration' }
            $observed = Get-CimInstance -ClassName Win32_Service -Filter "Name='$env:JC_HELPER_SERVICE_NAME'"
            if ($observed.PathName -ne $foreignCommand) { throw 'Refused installer overwrote external service configuration' }
        } finally {
            $restored = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{PathName=$originalCommand}
            if ($restored.ReturnValue -ne 0) { throw 'Could not restore fixture-owned service configuration' }
        }
        Write-Host 'PASS: foreign SCM configuration refused and preserved'
        Write-Host 'RUN: actual ordinary-user native control and account-scoped recovery'
        & $env:JC_HELPER_CONTROL_IMAGE $env:JC_HELPER_SERVICE_IMAGE
        if ($LASTEXITCODE -ne 0) { throw 'Native control identity or recovery boundary failed' }
        Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$($certificate.Thumbprint)" -Force
        $trusted = $false
        Write-Host 'RUN: actual SCM restart, independent owned recovery and ordinary-user control denial without installer trust'
        & (Join-Path $env:JC_HELPER_NATIVE_BUILD 'Release/windows_recovery_test.exe') --service (Join-Path $directory $env:JC_HELPER_DRIVER_NAME)
        if ($LASTEXITCODE -ne 0) { throw 'Independent SCM recovery failed' }
    } else {
        if ($env:JC_HELPER_QT_SESSION_HOST) {
            Write-Host 'RUN: actual ordinary application, native helper, core DNS and transparent traffic'
            & $env:JC_HELPER_CONTROL_IMAGE --qt-session $env:JC_HELPER_SERVICE_IMAGE $env:JC_HELPER_QT_SESSION_HOST
        } else {
            Write-Host 'RUN: actual ordinary Qt authenticated control and cancellation'
            & $env:JC_HELPER_CONTROL_IMAGE --qt $env:JC_HELPER_SERVICE_IMAGE (Join-Path $env:JC_HELPER_NATIVE_BUILD 'Release/windows_control_qt_test.exe')
        }
        if ($LASTEXITCODE -ne 0) { throw 'Ordinary Qt native lifecycle failed' }
    }
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
               JC_HELPER_QT_CONTROL='true' if args.qt_control else 'false',
               JC_HELPER_QT_SESSION_HOST=str(args.session_host) if args.session_host else '',
               JC_HELPER_CONTROL_IMAGE=str(destination / 'control-validation.exe'),
               JC_HELPER_TEST_IMAGE=str(destination / 'helper-validation.exe'),
               JC_HELPER_SERVICE_IMAGE=str(destination / contract['executable']),
               JC_HELPER_SERVICE_NAME=contract['service'], JC_HELPER_DRIVER_NAME=contract['driver_library'],
               JC_HELPER_EXECUTABLE=contract['executable'], JC_HELPER_INSTALL_DIRECTORY=contract['install_directory'])
    suffix = '-session' if args.session_host else '-qt' if args.qt_control else ''
    script_path = output / ('validate-windows-helper' + suffix + '.ps1')
    script_path.write_text(script, encoding='utf-8')
    log_path = output / ('windows-helper' + suffix + '.log')
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
