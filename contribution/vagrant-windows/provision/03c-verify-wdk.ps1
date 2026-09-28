# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# 03c-verify-wdk.ps1 -- Verify the WDK installation before the driver build.
#
# Runs after :reload (run:"always") to gate build-kubearmor. Checks that:
#   1. wdm.h is present (WDK kernel headers)
#   2. WindowsKernelModeDriver10.0.props is present (MSBuild toolset for vcxproj)
#
# WDK 10.0.19041 was installed directly via WinRM in 03b-install-buildtools.ps1.
# This script just confirms the installation succeeded.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> [03c] Verifying WDK installation..."

# 1. Check WDK kernel headers
$wdkMarker = "${env:ProgramFiles(x86)}\Windows Kits\10\Include"
$wdmHeader = Get-ChildItem $wdkMarker -Filter "wdm.h" -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $wdmHeader) {
    Write-Error @"
WDK kernel headers not found (wdm.h missing).

WDK 10.0.19041 should have been installed by 03b-install-buildtools.ps1.
Check C:\wdk-install.log for details:
  vagrant ssh -c "powershell Get-Content C:\wdk-install.log"

Then re-run:
  vagrant provision --provision-with install-buildtools
"@
    exit 1
}
Write-Host "wdm.h      : $wdmHeader"

# 2. Check WindowsKernelModeDriver10.0 MSBuild toolset (needed by kubearmor.vcxproj)
$wdkToolset = Get-ChildItem "${env:ProgramFiles(x86)}\MSBuild\Microsoft\WindowsDriver" `
    -Filter "WindowsKernelModeDriver10.0.props" -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $wdkToolset) {
    Write-Warning "WindowsKernelModeDriver10.0.props not found. The VS integration VSIX may not have installed."
    Write-Warning "Driver build (MSBuild) will likely fail with MSB8020. Check C:\wdk-install.log"
} else {
    Write-Host "WDK toolset: $wdkToolset"
}

Write-Host "==> [03c] WDK verified."
