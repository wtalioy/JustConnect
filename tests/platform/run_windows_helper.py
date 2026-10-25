"""Validate protected Windows helper payloads on an ephemeral, elevated runner."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = 'github.com/wtalioy/JustConnect/corelib/internal/windowshelper'


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Windows':
        raise RuntimeError('Machine installation checks require a disposable Windows runner')
    os.chdir(ROOT)
    output = ROOT / 'build/coreabi'
    metadata = json.loads((output / 'windows-device.json').read_text(encoding='utf-8'))
    destination = Path(metadata['driver']).parent
    host = metadata['powershell_host']
    script = r'''
$ErrorActionPreference = 'Stop'
$certificate = $null
$trusted = $false
try {
    Write-Host 'RUN: create ephemeral signing key'
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=JustConnect ephemeral helper validation" -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    Write-Host 'RUN: trust ephemeral signing certificate'
    $root = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
    $root.Open('ReadWrite')
    try { $root.Add($certificate); $trusted = $true } finally { $root.Close() }
    $publisher = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($certificate.RawData)).ToLowerInvariant()
    $flags = "-X {package}.publisherSHA256=$publisher -X {package}.driverSHA256=$env:JC_HELPER_DRIVER_SHA256 -X {package}.licenseSHA256=$env:JC_HELPER_LICENSE_SHA256"
    Write-Host 'RUN: compile native helper validation image'
    & go -C corelib test -mod=readonly -c -ldflags $flags -o $env:JC_HELPER_TEST_IMAGE ./internal/windowshelper
    if ($LASTEXITCODE -ne 0) { throw 'Signed helper validation build failed' }
    Write-Host 'RUN: sign native helper validation image'
    $signature = Set-AuthenticodeSignature -LiteralPath $env:JC_HELPER_TEST_IMAGE -Certificate $certificate -HashAlgorithm SHA256
    if ($signature.Status -ne 'Valid') { throw "Validation image signature: $($signature.Status)" }
    Write-Host 'RUN: protected installation and durable state checks'
    & $env:JC_HELPER_TEST_IMAGE '-test.v' '-test.count=1' '-test.timeout=90s'
    if ($LASTEXITCODE -ne 0) { throw 'Protected helper validation failed' }
} finally {
    if ($trusted) { Remove-Item -LiteralPath "Cert:\LocalMachine\Root\$($certificate.Thumbprint)" -Force }
    if ($null -ne $certificate) { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($certificate.Thumbprint)" -Force -DeleteKey }
}
'''.replace('{package}', PACKAGE)
    env = dict(os.environ, CGO_ENABLED='0', GOTOOLCHAIN='local', GOWORK='off', GOENV='off',
               JC_HELPER_DRIVER_SHA256=metadata['driver_sha256'],
               JC_HELPER_LICENSE_SHA256=metadata['license_sha256'],
               JC_HELPER_TEST_IMAGE=str(destination / 'helper-validation.exe'))
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
