# Windows deployment script
# Usage: .\deploy-windows.ps1 -TargetName "JustConnect" -DisplayName "JustConnect" -BuildDir "build" -Architecture "amd64" -Nightly "false"

param(
    [string]$TargetName = "JustConnect",
    [string]$DisplayName = "JustConnect",
    [string]$BuildDir = "build",
    [string]$Architecture = "amd64",
    [string]$Nightly = "false"
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

# Download and extract core
$CoreReleasePath = if ($Nightly -eq "true") { "download/nightly" } else { "latest/download" }
$CoreUrl = "https://github.com/Mythologyli/zju-connect/releases/$CoreReleasePath/zju-connect-windows-$Architecture.zip"
$CoreZipPath = "zju-connect-windows-$Architecture.zip"
Invoke-WebRequest -Uri $CoreUrl -OutFile $CoreZipPath
Expand-Archive -Path $CoreZipPath -DestinationPath . -Force
Remove-Item -Path $CoreZipPath

# Copy additional files
Copy-Item -Path "../libs/wintun/bin/$Architecture/wintun.dll" -Destination .
Copy-Item -Path "../resource/qt.conf" -Destination .

& .\zju-connect.exe -version
if ($LASTEXITCODE -ne 0) {
    throw "Bundled core failed with exit code $LASTEXITCODE"
}

# Remove vc_redist executable
if ($Architecture -eq "amd64") {
    Remove-Item -Path vc_redist.x64.exe -ErrorAction SilentlyContinue
} else {
    Remove-Item -Path vc_redist.arm64.exe -ErrorAction SilentlyContinue
}

Pop-Location
