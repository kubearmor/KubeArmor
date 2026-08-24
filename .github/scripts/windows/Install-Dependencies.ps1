<#
.SYNOPSIS
    Verifies the Windows build environment and pre-generates build prerequisites.

.PARAMETER RepoRoot
    Absolute path to the repository root.

.DESCRIPTION
    Performs the following checks and setup steps before any compilation runs:

      1. MSBuild  — confirms the Visual Studio 2022 MSBuild binary is present.
      2. WiX v3   — confirms that WiX v3 MSBuild targets are installed
                    (looks for wix.targets under the MSBuildExtensionsPath).
      3. mc.exe   — locates the Message Compiler from the Windows SDK (x64 host),
                    then compiles KarmorLogs.man → MSG00001.bin inside the
                    driver source directory.
                    MSG00001.bin must live next to the driver source files;
                    MSBuild also runs mc.exe during the driver build but outputs
                    to OBJ\, so we run it explicitly here.

    If any check fails the script exits with a non-zero code, aborting the
    workflow before any expensive compile steps run.

.EXAMPLE
    .\Install-Dependencies.ps1 -RepoRoot D:\a\KubeArmor\KubeArmor
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$msbuild    = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
$driverSrc  = "$RepoRoot\pkg\KubeArmorWindowsDriver"

Write-Host ""
Write-Host "======================================================"
Write-Host " Dependency check"
Write-Host "======================================================"

# ── 1. MSBuild ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [1/3] MSBuild ---"
if (-not (Test-Path $msbuild)) {
    Write-Error "MSBuild not found at: $msbuild"
    exit 1
}
$msbuildVersion = (& $msbuild /version /nologo 2>&1 | Select-Object -First 1).Trim()
Write-Host "  [OK] MSBuild: $msbuildVersion"
Write-Host "       Path   : $msbuild"

# ── 2. WiX v3 MSBuild targets ─────────────────────────────────────────────────
Write-Host ""
Write-Host "--- [2/3] WiX v3 toolset ---"
$wixTargets = Get-ChildItem "${env:ProgramFiles(x86)}\MSBuild" -Recurse -Filter "wix.targets" `
    -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName

if (-not $wixTargets) {
    Write-Error "WiX v3 MSBuild targets (wix.targets) not found. " +
                "Install WiX Toolset v3.11 from https://wixtoolset.org/releases/v3.11/stable"
    exit 1
}
Write-Host "  [OK] WiX targets: $wixTargets"

# ── 3. Message Compiler (mc.exe) + generate MSG00001.bin ──────────────────────
Write-Host ""
Write-Host "--- [3/3] Message Compiler (mc.exe) ---"
$mcExe = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
    -Recurse -Filter "mc.exe" `
    | Where-Object { $_.FullName -match "x64" } `
    | Select-Object -First 1 -ExpandProperty FullName

if (-not $mcExe) {
    Write-Error "mc.exe not found under '${env:ProgramFiles(x86)}\Windows Kits\10\bin'. " +
                "Ensure the Windows SDK is installed."
    exit 1
}
Write-Host "  [OK] mc.exe: $mcExe"

Write-Host "  Running mc.exe on KarmorLogs.man ..."
Push-Location $driverSrc
try {
    & $mcExe KarmorLogs.man
    if ($LASTEXITCODE -ne 0) {
        Write-Error "mc.exe failed with exit code $LASTEXITCODE"
        exit 1
    }
    if (-not (Test-Path "MSG00001.bin")) {
        Write-Error "mc.exe succeeded but MSG00001.bin was not created in $driverSrc"
        exit 1
    }
    Write-Host "  [OK] MSG00001.bin generated in: $driverSrc"
} finally {
    Pop-Location
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "======================================================"
Write-Host " All dependencies verified. Build environment is ready."
Write-Host "======================================================"

