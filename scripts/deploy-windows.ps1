# Windows deployment script
# Usage: .\deploy-windows.ps1 -TargetName "JustConnect" -DisplayName "JustConnect" -BuildDir "build" -Architecture "amd64"

param(
    [string]$TargetName = "JustConnect",
    [string]$DisplayName = "JustConnect",
    [string]$BuildDir = "build",
    [string]$Architecture = "amd64"
)

$ErrorActionPreference = "Stop"

Import-Module -Name Microsoft.PowerShell.Utility

# Create output directory
New-Item -ItemType Directory -Path "$DisplayName" -Force
Push-Location "$DisplayName"

# Copy executable
Copy-Item -Path "../$BuildDir/Release/$TargetName.exe" -Destination .

# Run windeployqt
& windeployqt.exe "$TargetName.exe"
if ($LASTEXITCODE -ne 0) {
    throw "windeployqt failed with exit code $LASTEXITCODE"
}

Copy-Item -Path "../$BuildDir/core/zju-connect.exe" -Destination .
Copy-Item -Path "../$BuildDir/core/core-provenance" -Destination . -Recurse

# Copy additional files
Copy-Item -Path "../libs/wintun/bin/$Architecture/wintun.dll" -Destination .
Copy-Item -Path "../resource/qt.conf" -Destination .

python ../scripts/build-core.py --verify .
if ($LASTEXITCODE -ne 0) {
    throw "Bundled core verification failed with exit code $LASTEXITCODE"
}

# Remove vc_redist executable
if ($Architecture -eq "amd64") {
    Remove-Item -Path vc_redist.x64.exe -ErrorAction SilentlyContinue
} else {
    Remove-Item -Path vc_redist.arm64.exe -ErrorAction SilentlyContinue
}

Pop-Location
