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

# Ship the native app-local CRT used by the application, its helpers and Qt plugins.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$crt = & $vswhere -latest -products '*' -find "VC\Redist\MSVC\*\$Architecture\Microsoft.VC*.CRT\msvcp140.dll" |
    Sort-Object { [version](Get-Item -LiteralPath $_).Directory.Parent.Parent.Name } -Descending |
    Select-Object -First 1
if (!$crt) { throw "Missing Visual C++ redistributable files for $Architecture" }
$machine = @{ x64 = 0x8664; arm64 = 0xaa64 }[$Architecture]
$runtime = @{}
foreach ($dll in Get-ChildItem -LiteralPath (Split-Path -Parent $crt) -Filter '*.dll' -File) {
    $reader = [IO.BinaryReader]::new([IO.File]::OpenRead($dll.FullName))
    try {
        $reader.BaseStream.Position = 0x3c
        $reader.BaseStream.Position = $reader.ReadUInt32()
        if ($reader.ReadUInt32() -ne 0x4550) { throw "Invalid PE image: $($dll.Name)" }
        # The PE machine field also distinguishes hybrid CRT images.
        if ($reader.ReadUInt16() -eq $machine) {
            $runtime[$dll.Name] = $dll.FullName
        }
    } finally {
        $reader.Dispose()
    }
}

# Include delay imports and follow dependencies of newly selected runtime DLLs.
$pending = @(Get-ChildItem -Recurse -File | Where-Object { $_.Extension -in '.exe', '.dll' } | ForEach-Object FullName)
while ($pending.Count) {
    $imports = & llvm-readobj --coff-imports @pending
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect Windows package imports' }
    $pending = @(foreach ($line in $imports) {
        if ($line -match '^\s+Name: (\S+)$' -and $runtime.ContainsKey($Matches[1])) {
            $name = $Matches[1]
            $source = $runtime[$name]
            $runtime.Remove($name)
            Copy-Item -LiteralPath $source -Destination .
            $source
        }
    })
}

Pop-Location
