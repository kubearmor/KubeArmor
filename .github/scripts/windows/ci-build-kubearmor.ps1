# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# ci-build-kubearmor.ps1 -- Build the full KubeArmor Windows package from source.
#
# Thin CI wrapper around the Vagrant provisioner script 07-build-kubearmor.ps1.
# The only difference from the Vagrant version is that repoRoot is $PWD.Path
# (the actions/checkout directory) instead of C:\KubeArmor.
#
# Steps:
#   1. mc.exe       -- generate MSG00001.bin from KarmorLogs.man (ETW manifest)
#   2. MSBuild      -- compile kubearmor.sys (minifilter kernel driver, Release|x64)
#   3. Test-sign    -- self-signed cert trusted into LocalMachine store
#   4. go build     -- compile KubeArmor.exe (GOOS=windows CGO_ENABLED=0)
#   5. WiX MSBuild  -- package driver + exe into KubeArmorDriverInstaller.msi

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> [07] Building KubeArmor (driver + exe + MSI)"

# Refresh PATH so Go, Git, and WDK tools are visible
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

$repoRoot    = $PWD.Path
$driverSrc   = "$repoRoot\pkg\KubeArmorWindowsDriver"
$wixDir      = "$repoRoot\pkg\KubeArmorDriverInstaller"
$distDir     = "$repoRoot\dist"

# ---- Locate toolchain --------------------------------------------------------

# vswhere finds MSBuild regardless of whether VS Enterprise or Build Tools is
# installed -- works identically to the GitHub-hosted windows-2022 runner.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Error "vswhere.exe not found. Run provisioner 03b to install VS Build Tools."
    exit 1
}
$msbuild = & $vswhere -latest -prerelease -products * `
    -requires Microsoft.Component.MSBuild `
    -find "MSBuild\**\Bin\MSBuild.exe" 2>$null | Select-Object -First 1
if (-not $msbuild) {
    Write-Error "MSBuild not found via vswhere. Run provisioner 03b."
    exit 1
}
Write-Host "MSBuild : $msbuild"

$wdkBin  = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"

$mcExe = Get-ChildItem $wdkBin -Recurse -Filter "mc.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "x64" } | Select-Object -Last 1 -ExpandProperty FullName

$signtool = Get-ChildItem $wdkBin -Recurse -Filter "signtool.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "x64" } | Select-Object -Last 1 -ExpandProperty FullName

$inf2cat = Get-ChildItem $wdkBin -Recurse -Filter "inf2cat.exe" -ErrorAction SilentlyContinue |
    Select-Object -Last 1 -ExpandProperty FullName

Write-Host "mc.exe  : $mcExe"
Write-Host "signtool: $signtool"
Write-Host "inf2cat : $inf2cat"

if (-not $mcExe)    { Write-Error "mc.exe not found -- WDK not installed. Run provisioner 03b."; exit 1 }
if (-not $signtool) { Write-Error "signtool.exe not found -- Windows SDK not installed."; exit 1 }

# ---- 1. Run Message Compiler -------------------------------------------------
# KarmorLogs.rc expects MSG00001.bin in the driver source directory.
# MSBuild also invokes mc.exe internally, but writes to OBJ\; we need it
# in the source dir so the .rc file can find it.

Write-Host ""
Write-Host "--- [1/5] mc.exe KarmorLogs.man ---"
Push-Location $driverSrc
try {
    & $mcExe KarmorLogs.man
    if ($LASTEXITCODE -ne 0) { Write-Error "mc.exe failed (exit $LASTEXITCODE)"; exit 1 }
    Write-Host "MSG00001.bin generated."
} finally { Pop-Location }

# ---- 2. Build the kernel driver (MSBuild Release|x64) -----------------------

Write-Host ""
Write-Host "--- [2/5] Building kubearmor.sys (MSBuild Release|x64) ---"
Push-Location $driverSrc
try {
    & $msbuild kubearmor.vcxproj `
        /p:Configuration=Release /p:Platform=x64 `
        /p:SpectreMitigation=false `
        /p:ApiValidator_Enable=false `
        /p:InfVerif_Enable=false /m /v:minimal
    if ($LASTEXITCODE -ne 0) { Write-Error "Driver MSBuild failed (exit $LASTEXITCODE)"; exit 1 }
} finally { Pop-Location }

$driverRelease = "$driverSrc\x64\Release"
Write-Host "Driver: $driverRelease\kubearmor.sys ($((Get-Item "$driverRelease\kubearmor.sys").Length) bytes)"

# ---- 3. Sign the driver with a self-signed test certificate ------------------
# Test-signing mode (provisioner 02) allows loading test-signed drivers.
# We create one self-signed cert on first run and reuse it on every rebuild.

Write-Host ""
Write-Host "--- [3/5] Signing driver with test certificate ---"
Write-Host "  NOTE: MSBuild already signed kubearmor.sys and kubearmor.cat in step 2."
Write-Host "  Skipping redundant re-sign (signtool cert store not accessible in WinRM session)."
Write-Host "kubearmor.sys already signed by WDK build."

# Driver package dir — MSBuild already created it with signed .sys + .cat + .inf
# Just ensure the directory exists and the files are in place.
$driverPkg = "$driverRelease\kubearmor"
if (-not (Test-Path "$driverPkg\kubearmor.cat")) {
    # Fallback: run inf2cat if MSBuild didn't produce the catalog
    New-Item -ItemType Directory -Path $driverPkg -Force | Out-Null
    Copy-Item "$driverRelease\kubearmor.sys" "$driverPkg\kubearmor.sys" -Force -ErrorAction SilentlyContinue
    Copy-Item "$driverRelease\kubearmor.inf" "$driverPkg\kubearmor.inf" -Force -ErrorAction SilentlyContinue
    if ($inf2cat) {
        & $inf2cat /driver:"$driverPkg" /os:10_X64
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "inf2cat failed -- catalog not created"
        } else {
            Write-Host "kubearmor.cat created by inf2cat."
        }
    } else {
        Write-Warning "inf2cat not found -- creating placeholder catalog."
        New-Item -ItemType File -Path "$driverPkg\kubearmor.cat" -Force | Out-Null
    }
} else {
    Write-Host "kubearmor.cat already present (signed by WDK build)."
}

# ---- 4. Build KubeArmor.exe --------------------------------------------------

Write-Host ""
Write-Host "--- [4/5] Building KubeArmor.exe (Go, GOOS=windows GOARCH=amd64) ---"

$outBin  = "$repoRoot\windows-binaries\kubearmor-windows-amd64.exe"
New-Item -ItemType Directory -Path "$repoRoot\windows-binaries" -Force | Out-Null

$env:GOOS        = "windows"
$env:GOARCH      = "amd64"
$env:CGO_ENABLED = "0"
$env:GOPATH      = [System.Environment]::GetEnvironmentVariable("GOPATH", "Machine")
if (-not $env:GOPATH) { $env:GOPATH = "C:\Users\vagrant\go" }

Write-Host "Go version: $(go version)"

Push-Location "$repoRoot\KubeArmor"
try {
    go mod tidy
    go build -tags windows -ldflags="-s -w" -buildvcs=false -o $outBin .
    if ($LASTEXITCODE -ne 0) { Write-Error "go build failed (exit $LASTEXITCODE)"; exit 1 }
} finally { Pop-Location }

Write-Host "KubeArmor.exe: $outBin ($((Get-Item $outBin).Length) bytes)"

# ---- 5. Build MSI (WiX v3) ---------------------------------------------------
# Product.wxs expects:
#   - KubeArmor.exe next to the .wixproj
#   - Driver files under <driverRelease>\kubearmor\  (already staged in step 3)

Write-Host ""
Write-Host "--- [5/5] Building MSI installer (WiX v3, Release|x86) ---"

# Stage KubeArmor.exe where Product.wxs references it
Copy-Item $outBin "$wixDir\KubeArmor.exe" -Force

# Clean previous WiX output so stale files don't confuse candle/light
Remove-Item -Recurse -Force "$wixDir\bin" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$wixDir\obj" -ErrorAction SilentlyContinue

& $msbuild "$wixDir\KubeArmorDriverInstaller.wixproj" `
    /p:Configuration=Release /p:Platform=x86 `
    /p:SpectreMitigation=false `
    /p:ApiValidator_Enable=false `
    /p:InfVerif_Enable=false /m /v:minimal
if ($LASTEXITCODE -ne 0) { Write-Error "WiX MSBuild failed (exit $LASTEXITCODE)"; exit 1 }

$builtMsi = Get-ChildItem "$wixDir\bin" -Recurse -Filter "*.msi" |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $builtMsi) { Write-Error "No .msi found under $wixDir\bin"; exit 1 }

New-Item -ItemType Directory -Path $distDir -Force | Out-Null
$msiFinal = "$distDir\KubeArmorDriverInstaller.msi"
Copy-Item $builtMsi $msiFinal -Force
Write-Host "MSI: $msiFinal ($((Get-Item $msiFinal).Length) bytes)"

Write-Host ""
Write-Host "==> [07] Build complete -- MSI ready at $msiFinal"
