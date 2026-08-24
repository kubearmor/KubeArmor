<#
.SYNOPSIS
    Builds all Windows KubeArmor artifacts: kernel driver, service binary, and MSI installer.

.PARAMETER Version
    The release version string (e.g. v1.5.0). Injected into the Go binary via
    ldflags and used to name the output MSI in dist\.

.PARAMETER RepoRoot
    Absolute path to the repository root.

.DESCRIPTION
    Assumes Install-Dependencies.ps1 has already run successfully (MSG00001.bin
    is present, WiX v3 is installed). Runs the three compilation stages:

      Step 1 — Kernel driver (MSBuild, Release|x64)
               Builds kubearmor.vcxproj with InfVerif disabled (no WHQL
               network in CI).

      Step 2 — Go service binary (GOOS=windows GOARCH=amd64, CGO_ENABLED=0)
               Produces windows-binaries\kubearmor-windows-amd64.exe with
               the version string embedded via ldflags.

      Step 3 — WiX MSI installer (MSBuild, Release|x86)
               WiX v3 uses "x86" as its MSBuild platform token; the 64-bit
               target is declared inside Product.wxs (Platform="x64",
               Win64="yes"). The ProjectReference to the driver vcxproj has
               AdditionalProperties=Platform=x64 so the driver TargetDir
               resolves to x64\Release\ correctly.
               Stages driver files and the exe, cleans stale WiX output, then
               copies the generated MSI to dist\.

.EXAMPLE
    .\Build-WindowsArtifacts.ps1 -Version v1.5.0 -RepoRoot D:\a\KubeArmor\KubeArmor
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$msbuild       = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
$driverSrc     = "$RepoRoot\pkg\KubeArmorWindowsDriver"
$driverRelease = "$driverSrc\x64\Release"
$wixDir        = "$RepoRoot\pkg\KubeArmorDriverInstaller"
$outBin        = "$RepoRoot\windows-binaries\kubearmor-windows-amd64.exe"

# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Kernel driver — Release|x64
# ──────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "======================================================"
Write-Host " Step 1/3 — Kernel driver (Release|x64)"
Write-Host "======================================================"

Push-Location $driverSrc
try {
    & $msbuild kubearmor.vcxproj `
        /p:Configuration=Release `
        /p:Platform=x64 `
        /p:InfVerif_Enable=false `
        /m `
        /v:minimal

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Driver MSBuild failed with exit code $LASTEXITCODE"
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host "Driver artifacts in: $driverRelease"

# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Go service binary
# ──────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "======================================================"
Write-Host " Step 2/3 — Go binary (GOOS=windows GOARCH=amd64)"
Write-Host "======================================================"

New-Item -ItemType Directory -Path "$RepoRoot\windows-binaries" -Force | Out-Null

$env:GOOS        = "windows"
$env:GOARCH      = "amd64"
$env:CGO_ENABLED = "0"

Push-Location "$RepoRoot\KubeArmor"
try {
    go build `
        -tags windows `
        "-ldflags=-s -w -X main.version=$Version" `
        -o $outBin `
        .

    if ($LASTEXITCODE -ne 0) {
        Write-Error "go build failed with exit code $LASTEXITCODE"
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host "Built: $outBin"

# ──────────────────────────────────────────────────────────────────────────────
# Step 3: WiX MSI installer — Release|x86
# ──────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "======================================================"
Write-Host " Step 3/3 — WiX MSI installer (Release|x86)"
Write-Host "======================================================"

# Pre-flight
Write-Host "--- Pre-flight artifact check ---"
foreach ($f in @($outBin, "$driverRelease\kubearmor.sys", "$driverRelease\kubearmor.inf")) {
    if (-not (Test-Path $f)) { Write-Error "Missing artifact: $f"; exit 1 }
    Write-Host "  [OK] $f"
}

# Stage driver files into the sub-dir expected by Product.wxs
$driverPkgDir = "$driverRelease\kubearmor"
New-Item -ItemType Directory -Path $driverPkgDir -Force | Out-Null
Copy-Item "$driverRelease\kubearmor.sys" "$driverPkgDir\kubearmor.sys" -Force
Copy-Item "$driverRelease\kubearmor.inf" "$driverPkgDir\kubearmor.inf" -Force
$catSrc = "$driverRelease\kubearmor.cat"
if (Test-Path $catSrc) {
    Copy-Item $catSrc "$driverPkgDir\kubearmor.cat" -Force
} else {
    # Empty placeholder so WiX does not error on a missing source file
    New-Item -ItemType File -Path "$driverPkgDir\kubearmor.cat" -Force | Out-Null
}
Write-Host "Driver files staged to: $driverPkgDir"

# Stage the exe where Product.wxs expects it
Copy-Item $outBin "$wixDir\KubeArmor.exe" -Force
Write-Host "Staged EXE to: $wixDir\KubeArmor.exe"

# Clean stale WiX output from any prior run
Remove-Item -Recurse -Force "$wixDir\bin" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$wixDir\obj" -ErrorAction SilentlyContinue

# Build MSI
Write-Host "--- Starting WiX MSBuild ---"
& $msbuild "$wixDir\KubeArmorDriverInstaller.wixproj" `
    /p:Configuration=Release `
    /p:Platform=x86 `
    /p:InfVerif_Enable=false `
    /m `
    /v:normal

if ($LASTEXITCODE -ne 0) {
    Write-Error "WiX MSBuild failed with exit code $LASTEXITCODE"
    exit 1
}

# Copy MSI to dist\
$distDir = "$RepoRoot\dist"
New-Item -ItemType Directory -Path $distDir -Force | Out-Null
$msiPath = Get-ChildItem "$wixDir\bin" -Recurse -Filter "*.msi" `
    | Select-Object -First 1 -ExpandProperty FullName

if (-not $msiPath) {
    Write-Error "No *.msi found under $wixDir\bin"
    exit 1
}

$msiDest = "$distDir\kubearmor_${Version}_Windows_x86_64.msi"
Copy-Item $msiPath $msiDest -Force
Write-Host "Created: $msiDest"

Write-Host ""
Write-Host "======================================================"
Write-Host " All build steps completed successfully."
Write-Host "======================================================"

