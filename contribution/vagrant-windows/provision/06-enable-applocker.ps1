# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor
#
# 06-enable-applocker.ps1 -- Enable AppLocker (Application Identity service)
#
# AppLocker enforcement requires the Application Identity service (AppIDSvc)
# to be running. On Windows Server 2022 it is installed but set to Manual
# startup by default.
#
# This script:
#   1. Sets AppIDSvc to Automatic startup
#   2. Starts the service
#   3. Enables the three AppLocker event-log channels that
#      KubeArmor's AppLockerPoller reads from
#   4. Applies a default "allow all" AppLocker policy so that the
#      policy engine is active (required for block rules to work)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> [06] Enabling AppLocker"

# -- Application Identity service --------------------------------------------
$svc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($null -eq $svc) {
    Write-Error "AppIDSvc not found -- is this a supported Windows edition?"
    exit 1
}

# Use sc.exe instead of Set-Service (AppIDSvc is a protected service
# and Set-Service fails with "description cannot be configured")
sc.exe config AppIDSvc start= auto | Out-Null
net start AppIDSvc 2>$null; $true

$svc = Get-Service -Name AppIDSvc
Write-Host "AppIDSvc status: $($svc.Status)"
if ($svc.Status -ne "Running") {
    Write-Error "AppIDSvc failed to start. AppLocker enforcement will not work."
    exit 1
}

# -- Enable AppLocker event-log channels -------------------------------------
$channels = @(
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-AppLocker/Packaged app-Execution"
)
foreach ($ch in $channels) {
    wevtutil sl $ch /e:true 2>$null
    Write-Host "Enabled event channel: $ch"
}

# -- Apply a baseline "allow everything" AppLocker policy -------------------
# AppLocker only enforces block rules when a policy is active.
# Without any policy, the engine is in "not configured" state and all
# deny rules added later are silently ignored.
# We apply a minimal allow-all policy to activate the engine.
$allowAllXml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2"
                  Name="Allow All (Everyone)" Description="" 
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="12e5c850-205b-42fa-b4c6-e7e8b67272dc"
                  Name="Allow All Scripts (Everyone)" Description=""
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="Enabled">
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba"
                       Name="Allow All Appx" Description=""
                       UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly">
    <FilePathRule Id="b882379b-2eeb-4375-9762-b92476b77259"
                  Name="Allow All DLLs (Everyone)" Description=""
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePathRule Id="19ae66bf-e9db-484c-8f9d-16a7396644eb"
                  Name="Allow All MSI (Everyone)" Description=""
                  UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

$tmpXml = [System.IO.Path]::GetTempFileName() + ".xml"
$allowAllXml | Set-Content -Path $tmpXml -Encoding UTF8
Set-AppLockerPolicy -XMLPolicy $tmpXml
Remove-Item $tmpXml -Force

Write-Host "Baseline AppLocker allow-all policy applied."
Write-Host "==> [06] AppLocker enabled and ready"
