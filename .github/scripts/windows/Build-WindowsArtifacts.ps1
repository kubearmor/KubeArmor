[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Error "vswhere.exe not found. Visual Studio Build Tools required."
    exit 1
}
$msbuild = & $vswhere -latest -prerelease -products * `
    -requires Microsoft.Component.MSBuild `
    -find "MSBuild\**\Bin\MSBuild.exe" 2>$null | Select-Object -First 1
if (-not $msbuild) {
    Write-Error "MSBuild not found via vswhere."
    exit 1
}
Write-Host "MSBuild : $msbuild"
$driverSrc     = "$RepoRoot\pkg\KubeArmorWindowsDriver"
$driverRelease = "$driverSrc\x64\Release"
$wixDir        = "$RepoRoot\pkg\KubeArmorDriverInstaller"
$outBin        = "$RepoRoot\windows-binaries\kubearmor-windows-amd64.exe"

# --- Build kernel driver ---

Write-Host "::group::Build kernel driver (Release|x64)"
Write-Host "Project : $driverSrc\kubearmor.vcxproj"
Write-Host "Output  : $driverRelease"

Push-Location $driverSrc
try {
    # Use minimal verbosity normally; MSBuild errors always print regardless of verbosity level
    & $msbuild kubearmor.vcxproj /p:Configuration=Release /p:Platform=x64 /p:InfVerif_Enable=false /m /v:minimal
    if ($LASTEXITCODE -ne 0) {
        Write-Host "::error::Driver MSBuild failed (exit $LASTEXITCODE). Check build output above for compiler errors."
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host "Driver output: $driverRelease\kubearmor.sys"
Write-Host "::endgroup::"

# --- Build Go service binary ---

Write-Host "::group::Build kubearmor.exe (GOOS=windows GOARCH=amd64)"
New-Item -ItemType Directory -Path "$RepoRoot\windows-binaries" -Force | Out-Null

$env:GOOS        = "windows"
$env:GOARCH      = "amd64"
$env:CGO_ENABLED = "0"

Write-Host "Version  : $Version"
Write-Host "Output   : $outBin"
Write-Host "Go version: $(go version)"

Push-Location "$RepoRoot\KubeArmor"
try {
    go build -tags windows "-ldflags=-s -w -X main.version=$Version" -o $outBin .
    if ($LASTEXITCODE -ne 0) {
        Write-Host "::error::go build failed (exit $LASTEXITCODE). Check output above for compilation errors."
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host "Binary size: $((Get-Item $outBin).Length) bytes"
Write-Host "::endgroup::"

# --- Build WiX MSI installer ---

Write-Host "::group::Build MSI installer (WiX v3, Release|x86)"

# Verify all artifacts exist before starting the MSI build
Write-Host "Pre-flight artifact check:"
foreach ($f in @($outBin, "$driverRelease\kubearmor.sys", "$driverRelease\kubearmor.inf")) {
    if (-not (Test-Path $f)) {
        Write-Host "::error::Missing artifact: $f"
        exit 1
    }
    Write-Host "  OK  $f"
}

# Stage driver files into the sub-directory Product.wxs references
$driverPkgDir = "$driverRelease\kubearmor"
New-Item -ItemType Directory -Path $driverPkgDir -Force | Out-Null
Copy-Item "$driverRelease\kubearmor.sys" "$driverPkgDir\kubearmor.sys" -Force
Copy-Item "$driverRelease\kubearmor.inf" "$driverPkgDir\kubearmor.inf" -Force

$catSrc = "$driverRelease\kubearmor.cat"
if (Test-Path $catSrc) {
    Copy-Item $catSrc "$driverPkgDir\kubearmor.cat" -Force
} else {
    # Placeholder so WiX doesn't error on a missing source file
    New-Item -ItemType File -Path "$driverPkgDir\kubearmor.cat" -Force | Out-Null
    Write-Host "::notice::kubearmor.cat not found — placeholder created. Driver is unsigned."
}

Copy-Item $outBin "$wixDir\KubeArmor.exe" -Force

Remove-Item -Recurse -Force "$wixDir\bin" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$wixDir\obj" -ErrorAction SilentlyContinue

# WiX v3 uses x86 as the MSBuild platform token; the 64-bit target is set
# inside Product.wxs. The ProjectReference pins Platform=x64 so the driver
# TargetDir resolves to x64\Release\ correctly.
Write-Host "Running WiX MSBuild..."
& $msbuild "$wixDir\KubeArmorDriverInstaller.wixproj" `
    /p:Configuration=Release /p:Platform=x86 /p:InfVerif_Enable=false /m /v:normal

if ($LASTEXITCODE -ne 0) {
    Write-Host "::error::WiX MSBuild failed (exit $LASTEXITCODE). Check candle/light output above."
    exit 1
}

$distDir = "$RepoRoot\dist"
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

$msiPath = Get-ChildItem "$wixDir\bin" -Recurse -Filter "*.msi" |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $msiPath) {
    Write-Host "::error::No *.msi found under $wixDir\bin — WiX build may have silently failed."
    exit 1
}

$msiDest = "$distDir\kubearmor_${Version}_Windows_x86_64.msi"
Copy-Item $msiPath $msiDest -Force
Write-Host "MSI: $msiDest ($((Get-Item $msiDest).Length) bytes)"
Write-Host "::endgroup::"
