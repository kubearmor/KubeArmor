<#
.SYNOPSIS
    Packages Windows build artifacts into a release ZIP, computes SHA-256
    checksums, and uploads everything to the GitHub release.

.PARAMETER Version
    The release tag (e.g. v1.5.0).

.PARAMETER Repo
    GitHub repository in "owner/name" format.

.PARAMETER RepoRoot
    Absolute path to the repository root.

.DESCRIPTION
    Runs the release publishing pipeline in two stages:

      Stage 1 — Archive & Checksums
               Assembles a versioned ZIP under dist\ containing:
                 kubearmor.exe, kubearmor.sys, kubearmor.inf,
                 kubearmor.cat (if present), and LICENSE.
               Archive name follows the goreleaser convention:
                 kubearmor_<version>_Windows_x86_64.zip
               SHA-256 hashes for all dist\*.zip and dist\*.msi are written
               to dist\sha256sums-windows.txt.

      Stage 2 — Upload
               Polls for up to 5 minutes (10 × 30 s) waiting for the
               goreleaser Linux job to create the GitHub release, then
               uploads all Windows ZIP, MSI, and checksum files via
               `gh release upload`.

.NOTES
    Requires the GH_TOKEN environment variable (set by the workflow via
    secrets.GITHUB_TOKEN).

.EXAMPLE
    $env:GH_TOKEN = "ghp_..."
    .\Publish-Release.ps1 -Version v1.5.0 -Repo Aryan-sharma11/KubeArmor -RepoRoot D:\a\KubeArmor\KubeArmor
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Repo,
    [Parameter(Mandatory)][string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$driverBase = "$RepoRoot\pkg\KubeArmorWindowsDriver"
$distDir    = "$RepoRoot\dist"

# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: Create release archive + checksums
# ──────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "======================================================"
Write-Host " Stage 1/2 — Create release archive & checksums"
Write-Host "======================================================"

$name       = "kubearmor_${Version}_Windows_x86_64"
$stagingDir = "$distDir\$name"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

$requiredFiles = @{
    "$RepoRoot\windows-binaries\kubearmor-windows-amd64.exe" = "$stagingDir\kubearmor.exe"
    "$driverBase\x64\Release\kubearmor.sys"                  = "$stagingDir\kubearmor.sys"
    "$driverBase\x64\Release\kubearmor.inf"                  = "$stagingDir\kubearmor.inf"
    "$RepoRoot\LICENSE"                                       = "$stagingDir\LICENSE"
}

Write-Host "--- Staging archive contents ---"
foreach ($src in $requiredFiles.Keys) {
    if (-not (Test-Path $src)) { Write-Error "Missing file for archive: $src"; exit 1 }
    Copy-Item $src $requiredFiles[$src] -Force
    Write-Host "  [+] $src"
}

$catSrc = "$driverBase\x64\Release\kubearmor.cat"
if (Test-Path $catSrc) {
    Copy-Item $catSrc "$stagingDir\kubearmor.cat" -Force
    Write-Host "  [+] $catSrc"
}

$zipPath = "$distDir\${name}.zip"
Compress-Archive -Path "$stagingDir\*" -DestinationPath $zipPath -Force
Write-Host "Created: $zipPath"

# SHA-256 checksums for .zip and .msi
$checksumFile = "$distDir\sha256sums-windows.txt"
Write-Host "--- SHA-256 checksums ---"
Get-ChildItem "$distDir\*.zip", "$distDir\*.msi" -ErrorAction SilentlyContinue | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$hash  $($_.Name)" | Out-File -Append $checksumFile -Encoding utf8
    Write-Host "  $hash  $($_.Name)"
}
Write-Host "Checksums written to: $checksumFile"

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: Upload to GitHub Release
# ──────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "======================================================"
Write-Host " Stage 2/2 — Upload assets to GitHub release $Version"
Write-Host "======================================================"

# Poll until the goreleaser Linux job creates the release (up to 5 min)
$found = $false
for ($i = 1; $i -le 10; $i++) {
    gh release view $Version --repo $Repo 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Release $Version is available."
        $found = $true
        break
    }
    Write-Host "Attempt $i/10 — release not yet available. Retrying in 30 s ..."
    Start-Sleep -Seconds 30
}

if (-not $found) {
    Write-Error "Release $Version was not found after 5 minutes. Aborting upload."
    exit 1
}

$assets = (Get-ChildItem `
    "$distDir\*.zip", "$distDir\*.msi", "$distDir\sha256sums-windows.txt" `
    -ErrorAction SilentlyContinue).FullName

if (-not $assets) {
    Write-Error "No assets found in $distDir to upload."
    exit 1
}

gh release upload $Version @assets --repo $Repo --clobber

if ($LASTEXITCODE -ne 0) {
    Write-Error "gh release upload failed with exit code $LASTEXITCODE"
    exit 1
}

Write-Host ""
Write-Host "======================================================"
Write-Host " Release $Version published successfully."
Write-Host "======================================================"

