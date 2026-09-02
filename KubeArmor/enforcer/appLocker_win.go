// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build windows
// +build windows

package enforcer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// appLockerTemplate is the full AppLocker XML policy we apply.
//
// Five %s placeholders in order:
//
//	[0] = Exe rules
//	[1] = Appx rules
//	[2] = Dll rules
//	[3] = Script rules
//	[4] = Msi rules
const appLockerTemplate = `
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="KubeArmor Default Allow All (Everyone)" Description="KubeArmor Default Allow" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d3" Name="KubeArmor Default Allow All (AppPackages)" Description="KubeArmor Default Allow" UserOrGroupSid="S-1-15-2-1" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
	%s
  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="Enabled">
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="KubeArmor Default Allow All Appx" Description="KubeArmor Default Allow" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
	%s
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="Enabled">
    <FilePathRule Id="b882379b-2eeb-4375-9762-b92476b77259" Name="KubeArmor Default Allow All (Everyone)" Description="KubeArmor Default Allow" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="b882379b-2eeb-4375-9762-b92476b7725a" Name="KubeArmor Default Allow All (AppPackages)" Description="KubeArmor Default Allow" UserOrGroupSid="S-1-15-2-1" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
	%s
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="12e5c850-205b-42fa-b4c6-e7e8b67272dc" Name="KubeArmor Default Allow All (Everyone)" Description="KubeArmor Default Allow" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="12e5c850-205b-42fa-b4c6-e7e8b67272dd" Name="KubeArmor Default Allow All (AppPackages)" Description="KubeArmor Default Allow" UserOrGroupSid="S-1-15-2-1" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
	%s
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePathRule Id="19ae66bf-e9db-484c-8f9d-16a7396644eb" Name="KubeArmor Default Allow All (Everyone)" Description="KubeArmor Default Allow" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="19ae66bf-e9db-484c-8f9d-16a7396644ec" Name="KubeArmor Default Allow All (AppPackages)" Description="KubeArmor Default Allow" UserOrGroupSid="S-1-15-2-1" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
	%s
  </RuleCollection>
</AppLockerPolicy>
`

type collectionRouting struct {
	Exe    bool
	Appx   bool
	Dll    bool
	Script bool
	Msi    bool
}

// classifyForAppLocker decides which AppLocker collections should receive a deny rule.
//
// IMPORTANT: The AppLocker "Appx" collection enforces on package *publisher identity*
// (FilePublisherRule), NOT on file paths. FilePathRule entries in the Appx collection
// are silently misinterpreted and end up matching entire package families, causing all
// packaged apps to be blocked when only one is targeted.
//
// Therefore we NEVER route rules into the Appx collection via file-path rules.
// Packaged app executables (in WindowsApps) are routed into the Exe collection instead,
// where FilePathRule with a wildcard (e.g. *\Notepad.exe) works correctly.
func classifyForAppLocker(path string) collectionRouting {
	lower := strings.ToLower(path)
	ext := filepath.Ext(lower)

	switch ext {
	case ".dll", ".ocx":
		return collectionRouting{Dll: true}
	case ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh":
		return collectionRouting{Script: true}
	case ".msi", ".msp", ".mst":
		return collectionRouting{Msi: true}
	}

	// All .exe paths — whether traditional Win32 or packaged app — go into the
	// Exe collection. FilePathRule is valid there and correctly matches by path.
	return collectionRouting{Exe: true}
}

// applyAppLockerPolicy converts KubeArmor host policies into an AppLocker XML
// policy and applies it via Set-AppLockerPolicy.
//
// Appx package policies should use the matchPackages stanza, which emits native
// FilePublisherRule entries into the Appx collection.
func applyAppLockerPolicy(secPolicies []tp.HostSecurityPolicy) error {
	var exeRules strings.Builder
	var appxRules strings.Builder
	var dllRules strings.Builder
	var scriptRules strings.Builder
	var msiRules strings.Builder

	for _, policy := range secPolicies {
		defaultAction := mapActionString(policy.Spec.Action)
		for _, pp := range policy.Spec.Process.MatchPaths {
			action := resolveAction(pp.Action, defaultAction)
			if action != ruleActionBlock {
				continue
			}

			// Normalize path: strip \??\ prefix, unify slashes
			path := strings.ReplaceAll(string(pp.Path), "/", "\\")
			if strings.HasPrefix(path, "\\??\\") {
				path = path[4:]
			}

			// Base name for display
			baseName := path
			if idx := strings.LastIndexAny(path, `/\`); idx >= 0 {
				baseName = path[idx+1:]
			}

			routing := classifyForAppLocker(path)

			// Build a standard FilePathRule string.
			// The rule Name encodes the KubeArmor policy metadata name in a
			// tagged suffix so the AppLocker poller can recover it from the
			// event log and set PolicyName correctly in the gRPC alert.
			buildRule := func(namePrefix string, overridePath string) string {
				targetPath := path
				if overridePath != "" {
					targetPath = overridePath
				}
				return fmt.Sprintf(`
    <FilePathRule Id="%s" Name="KubeArmor Block %s %s [kaPolicy:%s]" Description="KubeArmor Enforced" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%s" />
      </Conditions>
    </FilePathRule>`, uuid.New().String(), namePrefix, baseName, policy.Metadata["policyName"], targetPath)
			}

			if routing.Exe {
				// For packaged apps (WindowsApps), use *\basename wildcard so it
				// matches regardless of the versioned package directory.
				// For traditional EXEs, use the path as-is.
				var rulePath string
				if strings.Contains(strings.ToLower(path), "windowsapps") {
					rulePath = `*\` + baseName
				} else {
					rulePath = path
				}
				exeRules.WriteString(buildRule("Exe", rulePath))
			}
			if routing.Dll {
				dllRules.WriteString(buildRule("Dll", ""))
			}
			if routing.Script {
				scriptRules.WriteString(buildRule("Script", ""))
			}
			if routing.Msi {
				msiRules.WriteString(buildRule("Msi", ""))
			}
		}

		// === Process matchPackages — AppLocker Appx FilePublisherRule ===
		//
		// pkg.Name is treated as a regex/glob pattern matched against all installed
		// AppX package identity names. One FilePublisherRule is emitted per match,
		// using the exact package identity name and publisher from the system.
		for _, pkg := range policy.Spec.Process.MatchPackages {
			action := resolveAction(pkg.Action, defaultAction)
			if action != ruleActionBlock {
				continue
			}

			// Resolve the name pattern against all installed AppX packages.
			// publisherFilter is applied as an additional AND filter if specified.
			matched := resolvePackageMatches(pkg.Name, pkg.Publisher)
			if len(matched) == 0 {
				fmt.Printf("WARNING: matchPackages: no installed AppX packages matched pattern '%s' (publisher filter: '%s')\n",
					pkg.Name, pkg.Publisher)
				continue
			}

			for _, resolved := range matched {
				// Use the exact publisher from the installed package if the policy
				// didn't specify one, otherwise use the policy-provided value.
				publisherName := resolved.Publisher
				if pkg.Publisher != "" {
					publisherName = pkg.Publisher
				}
				if publisherName == "" {
					publisherName = "*"
				}

				fmt.Printf("INFO: matchPackages: blocking package '%s' (publisher: %s)\n",
					resolved.Name, publisherName)

				appxRules.WriteString(fmt.Sprintf(`
    <FilePublisherRule Id="%s" Name="KubeArmor Block Appx %s" Description="KubeArmor Enforced" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePublisherCondition PublisherName="%s" ProductName="%s" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>`, uuid.New().String(), resolved.Name, publisherName, resolved.Name))
			}
		}
	}

	xmlContent := fmt.Sprintf(appLockerTemplate,
		exeRules.String(),
		appxRules.String(),
		dllRules.String(),
		scriptRules.String(),
		msiRules.String())

	return applyPolicyXML(xmlContent)
}

// clearAppLockerPolicy removes all KubeArmor AppLocker enforcement rules
// but leaves the baseline Default Allow policies active. This is necessary
// because clearing the policy to "NotConfigured" breaks the system if DLL
// rules are active.
func clearAppLockerPolicy() error {
	xmlContent := fmt.Sprintf(appLockerTemplate, "", "", "", "", "")
	return applyPolicyXML(xmlContent)
}

// applyPolicyXML writes xmlContent to a temp file and calls Set-AppLockerPolicy.
func applyPolicyXML(xmlContent string) error {
	tmpFile, err := os.CreateTemp("", "applocker-*.xml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(xmlContent); err != nil {
		return fmt.Errorf("failed to write XML: %v", err)
	}
	tmpFile.Close()

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		fmt.Sprintf("Set-AppLockerPolicy -XMLPolicy '%s'", tmpFile.Name()))

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("AppLocker policy apply failed: %v, output: %s", err, string(out))
	}
	return nil
}
