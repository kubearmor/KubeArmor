# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# 05-install-ginkgo.ps1 -- Install the Ginkgo v2 CLI
# Pinned to the same commit used in ci-test-systemd.yml.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> [05] Installing Ginkgo CLI"

$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")
$env:GOPATH = [System.Environment]::GetEnvironmentVariable("GOPATH", "Machine")
if (-not $env:GOPATH) { $env:GOPATH = "C:\Users\vagrant\go" }

$GINKGO_REF = "9ff1646a26f77a4c0d33ddba3e6368c42c0e8842"

Write-Host "Installing ginkgo@$GINKGO_REF ..."
go install -mod=mod "github.com/onsi/ginkgo/v2/ginkgo@$GINKGO_REF"

# Make sure ginkgo is on the system PATH for all users
$ginkgoBin = "$env:GOPATH\bin"
$machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$ginkgoBin*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$machinePath;$ginkgoBin", "Machine")
}
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

ginkgo version
Write-Host "==> [05] Ginkgo installation complete"
