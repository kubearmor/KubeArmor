# Checks that MSBuild, WiX v3, and mc.exe are available, then runs mc.exe to
# generate MSG00001.bin next to the driver sources before the build starts.
# MSBuild also invokes mc.exe internally but writes to OBJ\; KarmorLogs.rc
# expects MSG00001.bin in the source directory, so we run it here first.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$msbuild   = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
$driverSrc = "$RepoRoot\pkg\KubeArmorWindowsDriver"

Write-Host "::group::Verify MSBuild"
if (-not (Test-Path $msbuild)) {
    Write-Host "::error::MSBuild not found: $msbuild"
    exit 1
}
Write-Host "MSBuild: $((& $msbuild /version /nologo 2>&1 | Select-Object -First 1).Trim())"
Write-Host "Path   : $msbuild"
Write-Host "::endgroup::"

Write-Host "::group::Verify WiX v3"
$wixTargets = Get-ChildItem "${env:ProgramFiles(x86)}\MSBuild" -Recurse -Filter "wix.targets" `
    -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

if (-not $wixTargets) {
    Write-Host "::error::WiX v3 not found. Install from https://wixtoolset.org/releases/v3.11/stable"
    exit 1
}
Write-Host "WiX targets: $wixTargets"
Write-Host "::endgroup::"

Write-Host "::group::Run Message Compiler (mc.exe)"
$mcExe = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter "mc.exe" |
    Where-Object { $_.FullName -match "x64" } |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $mcExe) {
    Write-Host "::error::mc.exe not found. Ensure the Windows SDK is installed."
    exit 1
}
Write-Host "mc.exe: $mcExe"
Write-Host "Working dir: $driverSrc"

Push-Location $driverSrc
try {
    & $mcExe KarmorLogs.man
    if ($LASTEXITCODE -ne 0) {
        Write-Host "::error::mc.exe exited with code $LASTEXITCODE"
        exit 1
    }
    if (-not (Test-Path "MSG00001.bin")) {
        Write-Host "::error::MSG00001.bin was not generated in $driverSrc"
        exit 1
    }
    Write-Host "MSG00001.bin generated successfully"
} finally {
    Pop-Location
}
Write-Host "::endgroup::"
