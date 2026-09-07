# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# 04-install-git.ps1 -- Install Git for Windows
# Required so `go mod download` can fetch modules that use git transports,
# and so contributors can commit from inside the VM.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> [04] Installing Git"

$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

if (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host "Git already installed: $(git --version)"
    exit 0
}

choco install git --yes --no-progress --params "/GitAndUnixToolsOnPath /WindowsTerminal"

# Refresh PATH
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

git --version
Write-Host "==> [04] Git installation complete"
