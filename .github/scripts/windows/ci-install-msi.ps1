# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# 09-install-from-msi.ps1 -- Install KubeArmor via the official MSI package.
#
# The MSI (built by the driver-build CI / release workflow) contains:
#   - kubearmor.sys  (minifilter kernel driver)
#   - kubearmor.inf / kubearmor.cat
#   - KubeArmor.exe  (userspace daemon, registered as KubeArmorSvc)
#
# The MSI custom actions handle driver INF registration, fltmc load, and
# service installation with the correct flags (-k8s=false -enableKubeArmorHostPolicy=true).
# This is the canonical onboarding path for production use.
#
# Usage:
#   Set KUBEARMOR_MSI_URL before running vagrant up / vagrant provision:
#
#     KUBEARMOR_MSI_URL=https://github.com/kubearmor/KubeArmor/releases/download/v1.x.y/KubeArmorDriverInstaller.msi \
#     vagrant provision --provision-with install-from-msi
#
#   If KUBEARMOR_MSI_URL is empty this script exits 0 (no-op) and the
#   fallback provisioners 07+08 (manual build/service) are used instead.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$msiUrl = $env:KUBEARMOR_MSI_URL
if ([string]::IsNullOrWhiteSpace($msiUrl)) {
    Write-Host "==> [09] KUBEARMOR_MSI_URL not set -- skipping MSI install (using build-from-source fallback)"
    exit 0
}

Write-Host "==> [09] Installing KubeArmor via MSI"
Write-Host "    URL: $msiUrl"

# -- Stop and uninstall any existing manually-installed service ----------------
$svc = Get-Service -Name KubeArmorSvc -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Removing existing KubeArmorSvc (manual install)..."
    # Try the built binary first, fall back to sc.exe
    $kaExe = "C:\KubeArmor\KubeArmor\KubeArmor.exe"
    if (Test-Path $kaExe) {
        & $kaExe stop      2>$null; $true
        Start-Sleep -Seconds 5
        & $kaExe uninstall 2>$null; $true
    } else {
        sc.exe stop KubeArmorSvc 2>$null; $true
        Start-Sleep -Seconds 5
        sc.exe delete KubeArmorSvc 2>$null; $true
    }
    Start-Sleep -Seconds 3
}

# -- Download the MSI ----------------------------------------------------------
$msiPath = Join-Path $env:TEMP "KubeArmorDriverInstaller.msi"
Write-Host "Downloading MSI to $msiPath ..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($msiUrl, $msiPath)
Write-Host "Download complete ($(( Get-Item $msiPath ).Length) bytes)"

# -- Install the MSI -----------------------------------------------------------
# /quiet      -- no UI
# /norestart  -- VM manages reboots via Vagrant :reload
# /l*v        -- verbose log for troubleshooting
$logPath = Join-Path $env:TEMP "KubeArmorDriverInstaller.log"
Write-Host "Running msiexec..."
$proc = Start-Process -FilePath "msiexec.exe" `
    -ArgumentList "/i `"$msiPath`" /quiet /norestart /l*v `"$logPath`"" `
    -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Host "---- MSI install log (last 50 lines) ----"
    Get-Content $logPath -Tail 50
    Write-Error "msiexec failed with exit code $($proc.ExitCode)"
    exit 1
}
Write-Host "MSI installed successfully"

# -- Wait for gRPC server to become ready -------------------------------------
Write-Host "Waiting for gRPC server on :32767..."
$deadline = (Get-Date).AddSeconds(60)
$ready    = $false
while ((Get-Date) -lt $deadline) {
    $conn = Test-NetConnection -ComputerName localhost -Port 32767 -WarningAction SilentlyContinue
    if ($conn.TcpTestSucceeded) { $ready = $true; break }
    Start-Sleep -Seconds 2
}

if (-not $ready) {
    Write-Warning "gRPC port 32767 did not open within 60 s -- check Event Viewer"
} else {
    Write-Host "gRPC server is accepting connections on :32767"
}

# -- Print service status ------------------------------------------------------
sc.exe query KubeArmorSvc

Write-Host "==> [09] MSI install complete"
