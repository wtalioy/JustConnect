"""Validate protected Windows helper payloads on an ephemeral, elevated runner."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

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
$ownedService = $false
$ownedDirectories = @()
$installers = @()
$qtOnly = $env:JC_HELPER_QT_CONTROL -eq 'true'
$qtOption = if ($qtOnly) { 'ON' } else { 'OFF' }
try {
    Write-Host 'RUN: configure native C++ installation authority'
    & cmake -S tests/platform/windows_device -B $env:JC_HELPER_NATIVE_BUILD '-DCMAKE_BUILD_TYPE=Release' "-DWINTUN_INCLUDE_DIR=$env:JC_HELPER_SDK_DIRECTORY" -A $env:JC_HELPER_CMAKE_ARCH "-DJC_HELPER_DRIVER_SHA256=$env:JC_HELPER_DRIVER_SHA256" "-DJC_HELPER_LICENSE_SHA256=$env:JC_HELPER_LICENSE_SHA256" "-DJC_WINDOWS_QT_CONTROL_TEST=$qtOption"
    if ($LASTEXITCODE -ne 0) { throw 'Native helper configuration failed' }
    & cmake --build $env:JC_HELPER_NATIVE_BUILD --config Release --target windows_installation_test windows_helper windows_recovery_test windows_control_test --parallel 3
    if ($LASTEXITCODE -ne 0) { throw 'Native helper installation build failed' }
    if (-not $qtOnly) {
        & cmake --build $env:JC_HELPER_NATIVE_BUILD --config Release --target windows_helper_previous windows_helper_startup_failure --parallel 3
        if ($LASTEXITCODE -ne 0) { throw 'Service replacement fixture build failed' }
    }
    $helperImage = Join-Path $env:JC_HELPER_NATIVE_BUILD "Release/$env:JC_HELPER_EXECUTABLE"
    if ((Get-AuthenticodeSignature -LiteralPath $helperImage).Status -ne 'NotSigned') {
        throw 'Certificate-free helper validation requires an unsigned image'
    }
    $facts = & $helperImage --version | ConvertFrom-Json
    $layout = Get-Content -Raw resource/network-helper-windows.json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $facts.revision -ne $env:GITHUB_SHA -or $facts.source_state -ne 'clean' -or
        $facts.protocol -ne $layout.protocol -or $facts.storage_version -ne $layout.storage_version -or
        $facts.identity_ready -ne $true -or
        $facts.driver_sha256 -ne $env:JC_HELPER_DRIVER_SHA256 -or $facts.license_sha256 -ne $env:JC_HELPER_LICENSE_SHA256) {
        throw 'Native helper read-only provenance or compiled authority mismatch'
    }
    if ($qtOnly -and -not $env:JC_HELPER_QT_SESSION_HOST) {
        & cmake --build $env:JC_HELPER_NATIVE_BUILD --config Release --target windows_control_qt_test --parallel 3
        if ($LASTEXITCODE -ne 0) { throw 'Ordinary Qt control build failed' }
    }
    Copy-Item -LiteralPath (Join-Path $env:JC_HELPER_NATIVE_BUILD 'Release/windows_control_test.exe') -Destination $env:JC_HELPER_CONTROL_IMAGE
    if (-not $qtOnly) {
        Copy-Item -LiteralPath (Join-Path $env:JC_HELPER_NATIVE_BUILD 'Release/windows_installation_test.exe') -Destination $env:JC_HELPER_TEST_IMAGE
        Write-Host 'RUN: unsigned C++ installation and ordinary-user boundaries'
        & $env:JC_HELPER_TEST_IMAGE
        if ($LASTEXITCODE -ne 0) { throw 'Unsigned native C++ installation failed' }
    }
    if (Get-Service -Name $env:JC_HELPER_SERVICE_NAME -ErrorAction SilentlyContinue) { throw 'Refuse pre-existing recovery service in fixture' }
    Copy-Item -LiteralPath (Join-Path $env:JC_HELPER_NATIVE_BUILD "Release/$env:JC_HELPER_EXECUTABLE") -Destination $env:JC_HELPER_SERVICE_IMAGE
    $hash = (Get-FileHash -LiteralPath $env:JC_HELPER_SERVICE_IMAGE -Algorithm SHA256).Hash.ToLowerInvariant()
    $directory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) (Join-Path $env:JC_HELPER_INSTALL_DIRECTORY $hash)
    if (Test-Path -LiteralPath $directory) { throw 'Refuse pre-existing service payload directory in fixture' }
    $ownedDirectories += $directory
    $ownedService = $true
    $tamperHelper = Join-Path $env:JC_HELPER_TAMPER_DIRECTORY $layout.executable
    Copy-Item -LiteralPath $helperImage -Destination $tamperHelper
    foreach ($payload in @($layout.driver_library, $layout.driver_license)) {
        $path = Join-Path $env:JC_HELPER_TAMPER_DIRECTORY $payload
        $original = [IO.File]::ReadAllBytes($path)
        try {
            $changed = [byte[]]$original.Clone()
            $changed[0] = $changed[0] -bxor 1
            [IO.File]::WriteAllBytes($path, $changed)
            & $tamperHelper --install
            if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $directory)) {
                throw 'Altered helper payload reached protected installation'
            }
        } finally { [IO.File]::WriteAllBytes($path, $original) }
    }
    Write-Host 'PASS: unsigned helper rejects altered driver and license before machine installation'

    if (-not $qtOnly) {
        $variants = @{}
        foreach ($variant in @('previous','startup_failure')) {
            $image = Join-Path $env:JC_HELPER_NATIVE_BUILD "$variant/Release/$env:JC_HELPER_EXECUTABLE"
            foreach ($payload in @($env:JC_HELPER_DRIVER_NAME,$layout.driver_license)) {
                Copy-Item -LiteralPath (Join-Path $env:JC_HELPER_SDK_DIRECTORY $payload) -Destination (Join-Path (Split-Path $image) $payload)
            }
            $identity = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
            $installedDirectory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) (Join-Path $env:JC_HELPER_INSTALL_DIRECTORY $identity)
            if (Test-Path -LiteralPath $installedDirectory) { throw 'Refuse pre-existing replacement fixture payload' }
            $ownedDirectories += $installedDirectory
            $variants[$variant] = @{source=$image;installed=(Join-Path $installedDirectory $env:JC_HELPER_EXECUTABLE)}
        }
        $previousInstalled = & $variants.previous.source --install
        if ($LASTEXITCODE -ne 0 -or $previousInstalled -ne $variants.previous.installed) { throw 'Prior service image installation failed' }
        $previousService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$env:JC_HELPER_SERVICE_NAME'"
        & (Join-Path $env:JC_HELPER_NATIVE_BUILD 'Release/windows_recovery_test.exe') --upgrade-busy $env:JC_HELPER_SERVICE_IMAGE
        if ($LASTEXITCODE -ne 0) { throw 'Replacement did not preserve live ownership' }
        $busyService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$env:JC_HELPER_SERVICE_NAME'"
        if ($busyService.PathName -ne $previousService.PathName -or $busyService.ProcessId -ne $previousService.ProcessId -or $busyService.State -ne 'Running') {
            throw 'Refused replacement disrupted the active recovery service'
        }
        $failedLog = Join-Path $env:JC_HELPER_NATIVE_BUILD 'service-startup-failure.log'
        $failed = Start-Process -FilePath $variants.startup_failure.source -ArgumentList '--install' -PassThru -NoNewWindow -RedirectStandardError $failedLog
        $failed.Handle | Out-Null
        $installers += $failed
        if (-not $failed.WaitForExit(30000) -or $null -eq $failed.ExitCode -or $failed.ExitCode -eq 0) { throw 'Broken replacement unexpectedly started or exceeded its deadline' }
        $rolledBack = Get-CimInstance -ClassName Win32_Service -Filter "Name='$env:JC_HELPER_SERVICE_NAME'"
        if ($rolledBack.PathName -ne $previousService.PathName -or $rolledBack.ProcessId -eq $previousService.ProcessId -or $rolledBack.State -ne 'Running' -or
            (Get-Process -Id $rolledBack.ProcessId).Path -ne $previousInstalled) { throw 'Failed replacement did not restore the actual previous service image' }
        Write-Host 'PASS: new image startup failure rolls back the original service and restarts its actual protected image'
        $firstLog = Join-Path $env:JC_HELPER_NATIVE_BUILD 'service-upgrade-first.txt'
        $secondLog = Join-Path $env:JC_HELPER_NATIVE_BUILD 'service-upgrade-second.txt'
        $first = Start-Process -FilePath $env:JC_HELPER_SERVICE_IMAGE -ArgumentList '--install' -PassThru -NoNewWindow -RedirectStandardOutput $firstLog
        $first.Handle | Out-Null
        $installers += $first
        $second = Start-Process -FilePath $env:JC_HELPER_SERVICE_IMAGE -ArgumentList '--install' -PassThru -NoNewWindow -RedirectStandardOutput $secondLog
        $second.Handle | Out-Null
        $installers += $second
        if (-not $first.WaitForExit(30000) -or -not $second.WaitForExit(30000) -or $first.ExitCode -ne 0 -or $second.ExitCode -ne 0) {
            throw 'Concurrent service replacement/reuse failed'
        }
        $expectedInstalled = Join-Path $directory $env:JC_HELPER_EXECUTABLE
        if ((Get-Content -Raw $firstLog).Trim() -ne $expectedInstalled -or (Get-Content -Raw $secondLog).Trim() -ne $expectedInstalled) {
            throw 'Concurrent replacements returned different installation identities'
        }
        $upgraded = Get-CimInstance -ClassName Win32_Service -Filter "Name='$env:JC_HELPER_SERVICE_NAME'"
        if ($upgraded.State -ne 'Running' -or (Get-Process -Id $upgraded.ProcessId).Path -ne $expectedInstalled) {
            throw 'Service does not execute the current protected image after replacement'
        }
        Write-Host 'PASS: two concurrent installers replace a previous protected image with one current running service'
    }

    Write-Host 'RUN: unsigned production C++ service install and idempotent reuse'
    $installed = & $env:JC_HELPER_SERVICE_IMAGE --install
    if ($LASTEXITCODE -ne 0 -or $installed -isnot [string]) { throw 'Recovery service installation failed' }
    $reused = & $env:JC_HELPER_SERVICE_IMAGE --install
    if ($LASTEXITCODE -ne 0 -or $reused -ne $installed) { throw 'Recovery service reuse changed its identity' }
    if (-not $qtOnly) {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$env:JC_HELPER_SERVICE_NAME'"
        $originalCommand = $service.PathName
        foreach ($foreignCommand in @("$originalCommand --unowned", ('"'+$env:JC_HELPER_SERVICE_IMAGE+'" --service'))) {
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
        }
        Write-Host 'PASS: foreign SCM arguments and unprotected image configuration refused and preserved'
        Write-Host 'RUN: actual ordinary-user native control and account-scoped recovery'
        & $env:JC_HELPER_CONTROL_IMAGE $env:JC_HELPER_SERVICE_IMAGE
        if ($LASTEXITCODE -ne 0) { throw 'Native control identity or recovery boundary failed' }
        Write-Host 'RUN: actual SCM restart, independent owned recovery and ordinary-user control denial without signing credentials'
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
    foreach ($installer in $installers) {
        if (-not $installer.HasExited) { $installer.Kill(); $installer.WaitForExit(5000) | Out-Null }
        $installer.Dispose()
    }
    if ($ownedService -and (Get-Service -Name $env:JC_HELPER_SERVICE_NAME -ErrorAction SilentlyContinue)) {
        Stop-Service -Name $env:JC_HELPER_SERVICE_NAME
        & sc.exe delete $env:JC_HELPER_SERVICE_NAME
        if ($LASTEXITCODE -ne 0) { throw 'Fixture service cleanup failed' }
    }
    foreach ($ownedDirectory in $ownedDirectories) { if (Test-Path -LiteralPath $ownedDirectory) { Remove-Item -LiteralPath $ownedDirectory -Recurse -Force } }
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
    with tempfile.TemporaryDirectory(prefix='justconnect-helper-') as directory, log_path.open('w', encoding='utf-8') as log:
        payload = Path(directory)
        shutil.copy2(metadata['driver'], payload / contract['driver_library'])
        shutil.copy2(metadata['license'], payload / contract['driver_license'])
        env['JC_HELPER_TAMPER_DIRECTORY'] = str(payload)
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
