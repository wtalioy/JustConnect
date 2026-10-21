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
& windeployqt.exe --release --translations "en,zh_CN" --skip-plugin-types qmltooling "$TargetName.exe"
if ($LASTEXITCODE -ne 0) {
    throw "windeployqt failed with exit code $LASTEXITCODE"
}

# windeployqt's language filter does not apply to Chromium locale packs.
Get-ChildItem -Path 'translations/qtwebengine_locales' -Filter '*.pak' |
    Where-Object { $_.Name -notin @('en-US.pak', 'zh-CN.pak') } | Remove-Item

Copy-Item -Path "../resource/qt.conf" -Destination .
Get-ChildItem -Filter 'vc_redist.*.exe' | Remove-Item

Pop-Location
