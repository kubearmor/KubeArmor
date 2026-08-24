# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# 03-install-go.ps1 -- Install the Go toolchain

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> [03] Installing Go toolchain"

# Refresh PATH to pick up Chocolatey from the previous provisioner
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

# Pin to the same Go version used in KubeArmor/go.mod
# Update this when go.mod's `go` directive changes.
$GO_VERSION = "1.24.4"

if (Get-Command go -ErrorAction SilentlyContinue) {
    $installed = (go version) -replace "go version go([0-9.]+).*", '$1'
    if ($installed -eq $GO_VERSION) {
        Write-Host "Go $GO_VERSION already installed."
        exit 0
    }
    Write-Host "Upgrading Go from $installed to $GO_VERSION"
}

Write-Host "Installing Go $GO_VERSION via Chocolatey..."
choco install golang --version=$GO_VERSION --yes --no-progress

# Persist Go paths for all future sessions / provisioners
$goPath  = "C:\Go\bin"
$goModCache = "C:\Users\vagrant\go\bin"
[System.Environment]::SetEnvironmentVariable("GOPATH", "C:\Users\vagrant\go", "Machine")
$machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$goPath*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$machinePath;$goPath;$goModCache", "Machine")
}
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

go version
Write-Host "==> [03] Go installation complete"
