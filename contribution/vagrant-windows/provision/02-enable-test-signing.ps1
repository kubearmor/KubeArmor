# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# 02-enable-test-signing.ps1 -- Enable test-signing boot mode
#
# Kernel-mode minifilter drivers (.sys) must be cryptographically signed.
# For development/test builds that are NOT EV-signed, Windows must be put
# into "test signing" mode so the OS accepts test-signed drivers.
#
# Secure Boot must be disabled at the firmware level first (the Vagrantfile
# sets --firmware bios, which means no Secure Boot at all -- this is correct).
#
# A reboot (handled by the :reload provisioner in the Vagrantfile) is
# required for bcdedit changes to take effect.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> [02] Enabling test-signing mode"

# Check current state
$current = bcdedit /enum '{current}' 2>&1 | Select-String "testsigning"
if ($current -match "Yes") {
    Write-Host "Test-signing is already enabled -- no change needed."
} else {
    bcdedit /set testsigning on
    Write-Host "Test-signing enabled. A reboot is required (handled by Vagrant)."
}

# Also disable the kernel integrity check for test-signed drivers on
# Server 2022 (equivalent to /nointegritychecks for older Windows).
# Note: on Server 2022 the boot option is named differently depending on
# whether Hyper-V / VBS is active. We set it unconditionally; if it's
# already in the right state bcdedit returns success silently.
bcdedit /set loadoptions DDISABLE_INTEGRITY_CHECKS 2>$null; $true
bcdedit /set nointegritychecks on                  2>$null; $true

Write-Host "==> [02] Test-signing configuration complete -- VM will reboot"
