# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# 01-system-prep.ps1 -- Basic Windows system preparation
# Sets execution policy, enables TLS 1.2, syncs the system clock,
# and disables IE Enhanced Security (which blocks winget/web downloads).

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> [01] System preparation started"

# Allow running local scripts (may fail if a higher-scope GPO is active -- that's OK)
try { Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop }
catch { Write-Host "ExecutionPolicy already managed by GPO -- skipping ($($_.Exception.Message))" }

# Force TLS 1.2 for all web requests in this session (required for
# Chocolatey, GitHub downloads, etc. on Server 2022 with defaults).
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Sync clock with the host before doing anything network-related
w32tm /resync /force 2>$null; $true

# Disable IE Enhanced Security Configuration (may not exist on Server Core)
$ieKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $ieKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue
$ieKeyUser = "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $ieKeyUser -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue

# Install Chocolatey package manager (used by subsequent provisioners)
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..."
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
} else {
    Write-Host "Chocolatey already installed: $(choco --version)"
}

# Refresh PATH so choco is available in the same session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

Write-Host "==> [01] System preparation complete"
