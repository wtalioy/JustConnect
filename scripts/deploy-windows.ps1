# Windows deployment script
# Usage: .\deploy-windows.ps1 -TargetName "JustConnect" -DisplayName "JustConnect" -BuildDir "build"

param(
    [string]$TargetName = "JustConnect",
    [string]$DisplayName = "JustConnect",
    [string]$BuildDir = "build",
    [ValidateSet('x64', 'arm64')][string]$Architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
)

$ErrorActionPreference = "Stop"

Import-Module -Name Microsoft.PowerShell.Utility

# Create output directory
New-Item -ItemType Directory -Path "$DisplayName" -Force
Push-Location "$DisplayName"

# Copy executable
Copy-Item -Path "../$BuildDir/Release/$TargetName.exe" -Destination .

# Install the CMake-selected embedded runtime next to the host.
cmake --install "../$BuildDir" --config Release --component CoreRuntime --prefix (Get-Location).Path
if ($LASTEXITCODE -ne 0) { throw "Embedded runtime installation failed" }
cmake --install "../$BuildDir/windows-helper" --config Release --component WindowsNetworkHelper --prefix (Get-Location).Path
if ($LASTEXITCODE -ne 0) { throw "Native network helper installation failed" }

# TUIO input requires an explicitly enabled generic plugin.
& windeployqt.exe --release --no-translations --no-compiler-runtime --exclude-plugins qtuiotouchplugin "$TargetName.exe"
if ($LASTEXITCODE -ne 0) {
    throw "windeployqt failed with exit code $LASTEXITCODE"
}

Copy-Item -Path "../resource/qt.conf" -Destination .

# Ship the native app-local CRT with both the ZIP and the installer.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$crt = & $vswhere -latest -products '*' -find "VC\Redist\MSVC\*\$Architecture\Microsoft.VC*.CRT\msvcp140.dll" |
    Sort-Object { [version](Get-Item -LiteralPath $_).Directory.Parent.Parent.Name } -Descending |
    Select-Object -First 1
if (!$crt) { throw "Missing Visual C++ redistributable files for $Architecture" }
Copy-Item -Path (Join-Path (Split-Path -Parent $crt) '*.dll') -Destination .

Pop-Location
