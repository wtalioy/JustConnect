# Windows deployment script
# Usage: .\deploy-windows.ps1 -TargetName "JustConnect" -DisplayName "JustConnect" -BuildDir "build"

param(
    [string]$TargetName = "JustConnect",
    [string]$DisplayName = "JustConnect",
    [string]$BuildDir = "build"
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

# Run windeployqt
& windeployqt.exe "$TargetName.exe"
if ($LASTEXITCODE -ne 0) {
    throw "windeployqt failed with exit code $LASTEXITCODE"
}

Copy-Item -Path "../resource/qt.conf" -Destination .
Get-ChildItem -Filter 'vc_redist.*.exe' | Remove-Item

Pop-Location
