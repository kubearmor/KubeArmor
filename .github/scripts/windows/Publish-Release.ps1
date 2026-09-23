[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$Repo,
    [Parameter(Mandatory)][string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$driverBase   = "$RepoRoot\pkg\KubeArmorWindowsDriver"
$distDir      = "$RepoRoot\dist"
$name         = "kubearmor_${Version}_Windows_x86_64"
$stagingDir   = "$distDir\$name"
$checksumFile = "$distDir\sha256sums-windows.txt"

# --- Create release archive ---

Write-Host "::group::Create release archive"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

$files = @{
    "$RepoRoot\windows-binaries\kubearmor-windows-amd64.exe" = "$stagingDir\kubearmor.exe"
    "$driverBase\x64\Release\kubearmor.sys"                  = "$stagingDir\kubearmor.sys"
    "$driverBase\x64\Release\kubearmor.inf"                  = "$stagingDir\kubearmor.inf"
    "$RepoRoot\LICENSE"                                       = "$stagingDir\LICENSE"
}

foreach ($src in $files.Keys) {
    if (-not (Test-Path $src)) {
        Write-Host "::error::Missing artifact: $src"
        exit 1
    }
    Copy-Item $src $files[$src] -Force
    Write-Host "  staged  $src"
}

$catSrc = "$driverBase\x64\Release\kubearmor.cat"
if (Test-Path $catSrc) {
    Copy-Item $catSrc "$stagingDir\kubearmor.cat" -Force
    Write-Host "  staged  $catSrc"
} else {
    Write-Host "::notice::kubearmor.cat not present — skipping (driver is unsigned)"
}

$zipDest = "$distDir\${name}.zip"
Compress-Archive -Path "$stagingDir\*" -DestinationPath $zipDest -Force
Write-Host "Archive : $zipDest ($((Get-Item $zipDest).Length) bytes)"
Write-Host "::endgroup::"

Write-Host "::group::SHA-256 checksums"
Get-ChildItem "$distDir\*.zip", "$distDir\*.msi" -ErrorAction SilentlyContinue | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$hash  $($_.Name)" | Out-File -Append $checksumFile -Encoding utf8
    Write-Host "$hash  $($_.Name)"
}
Write-Host "Checksums written to: $checksumFile"
Write-Host "::endgroup::"

# --- Upload to GitHub Release ---

# Wait for the goreleaser Linux job to create the release before uploading.
# Both jobs fire on the same tag push; the Windows build takes longer so the
# release is usually ready by the time we get here.
Write-Host "::group::Upload assets to GitHub release $Version"
$found = $false
for ($i = 1; $i -le 10; $i++) {
    gh release view $Version --repo $Repo 2>$null
    if ($LASTEXITCODE -eq 0) { $found = $true; break }
    Write-Host "  attempt $i/10 - not ready yet, retrying in 30s"
    Start-Sleep -Seconds 30
}

if (-not $found) {
    Write-Host "::error::Release $Version not found after 5 minutes. The goreleaser job may have failed."
    exit 1
}

$assets = (Get-ChildItem "$distDir\*.zip", "$distDir\*.msi", $checksumFile -ErrorAction SilentlyContinue).FullName
if (-not $assets) {
    Write-Host "::error::No assets found in $distDir to upload."
    exit 1
}

Write-Host "Uploading:"
$assets | ForEach-Object { Write-Host "  $_" }

gh release upload $Version @assets --repo $Repo --clobber
if ($LASTEXITCODE -ne 0) {
    Write-Host "::error::gh release upload failed (exit $LASTEXITCODE)"
    exit 1
}

Write-Host "Uploaded $($assets.Count) assets to release $Version"
Write-Host "::endgroup::"
