param(
    [Parameter(Mandatory)][string]$Payload,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
    [Parameter(Mandatory)][string]$OutputName
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Installer smoke test requires a disposable GitHub runner' }

function Invoke-Setup($File, $Arguments) {
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "$File exited with code $($process.ExitCode)" }
}

# Use the same official x86 compiler on both native Windows runners.
$compilerSetup = Join-Path $env:RUNNER_TEMP 'innosetup-7.1.1-x86.exe'
Invoke-WebRequest 'https://github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x86.exe' -OutFile $compilerSetup
if ((Get-FileHash -LiteralPath $compilerSetup).Hash -ne '03446e46f5da932e408881168c01afc59cc667cb5bc927d839c5526ace5cc0d3') {
    throw 'Inno Setup compiler download differs from the pinned release'
}
$compilerDir = Join-Path $env:RUNNER_TEMP 'inno-compiler'
$silent = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
Invoke-Setup $compilerSetup "$silent /CURRENTUSER /DIR=`"$compilerDir`""

$payloadRoot = (Resolve-Path -LiteralPath $Payload).Path
$machine = if ($Architecture -eq 'x64') { 'x64os' } else { 'arm64' }
$outDir = (Get-Location).Path
& (Join-Path $compilerDir 'ISCC.exe') "/DPayload=$payloadRoot" "/DAppVersion=$Version" "/DTargetArchitecture=$machine" `
    "/O$outDir" "/F$OutputName" (Join-Path $PSScriptRoot 'windows-installer.iss')

$installer = Join-Path $outDir "$OutputName.exe"
$app = Join-Path $env:LOCALAPPDATA 'Programs\JustConnect'
$shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'JustConnect.lnk'
if ((Test-Path -LiteralPath $app) -or (Test-Path -LiteralPath $shortcut)) { throw 'Installer smoke test requires a clean user profile' }
Invoke-Setup $installer $silent
$uninstaller = Join-Path $app 'unins000.exe'
try {
    if (!(Test-Path -LiteralPath $shortcut)) { throw 'Missing Start menu shortcut' }
    foreach ($file in Get-ChildItem -LiteralPath $payloadRoot -Recurse -File) {
        $relative = [IO.Path]::GetRelativePath($payloadRoot, $file.FullName)
        $installed = Join-Path $app $relative
        if ((Get-FileHash -LiteralPath $installed).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash) {
            throw "Installed file differs from the verified portable payload: $relative"
        }
    }
    $result = & (Join-Path $app 'JustConnect.exe') --core-self-test | ConvertFrom-Json
    if (!$result.ok -or $result.application_version -ne $Version -or $result.core.build.revision -ne $env:GITHUB_SHA) {
        throw 'Installed application failed its version and core self-test'
    }
} finally {
    Invoke-Setup $uninstaller $silent
}
if ((Test-Path -LiteralPath (Join-Path $app 'JustConnect.exe')) -or (Test-Path -LiteralPath $shortcut)) {
    throw 'Uninstall left the application or shortcut installed'
}
"sha256=$((Get-FileHash -LiteralPath $installer).Hash.ToLowerInvariant())" >> $env:GITHUB_OUTPUT
