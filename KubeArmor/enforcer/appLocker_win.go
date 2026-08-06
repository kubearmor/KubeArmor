//go:build windows
// +build windows

package enforcer

import (
	"fmt"
	"io/fs"
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
//   [0] = Exe rules
//   [1] = Appx rules
//   [2] = Dll rules
//   [3] = Script rules
//   [4] = Msi rules
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

// (Removed clearPolicyXML)

// buildAppxExeSet scans %ProgramFiles%\WindowsApps and returns a set of
// lowercase .exe basenames found there. All Packaged Apps install exclusively
// to this directory, so membership in this set definitively identifies a
// Packaged App executable.
//
// The scan is fast (<100 ms on typical systems) because WindowsApps contains
// ~100-500 executables total.
func buildAppxExeSet() map[string]struct{} {
	set := make(map[string]struct{})

	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	windowsAppsDir := filepath.Join(programFiles, "WindowsApps")

	_ = filepath.WalkDir(windowsAppsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Access denied on some subdirs is normal — skip silently.
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(path), ".exe") {
			set[strings.ToLower(filepath.Base(path))] = struct{}{}
		}
		return nil
	})

	return set
}

type collectionRouting struct {
	Exe    bool
	Appx   bool
	Dll    bool
	Script bool
	Msi    bool
}

// classifyForAppLocker decides which AppLocker collections should receive a deny rule.
func classifyForAppLocker(path string, appxSet map[string]struct{}) collectionRouting {
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

	// For .exe or no extension:
	if strings.ContainsAny(path, `/\`) {
		if strings.Contains(lower, "windowsapps") {
			return collectionRouting{Appx: true} // definitively a Packaged App
		}
		return collectionRouting{Exe: true} // definitively a traditional EXE
	}

	// Bare filename — look it up in the scanned Appx set
	_, isAppx := appxSet[lower]
	if isAppx {
		return collectionRouting{Exe: true, Appx: true}
	}
	return collectionRouting{Exe: true}
}

// applyAppLockerPolicy converts KubeArmor host policies into an AppLocker XML
// policy and applies it via Set-AppLockerPolicy.
//
// appxSet is the pre-built set of Packaged App exe names (from buildAppxExeSet).
// Pass an empty map if unavailable — rules will fall back to Exe-only.
func applyAppLockerPolicy(secPolicies []tp.HostSecurityPolicy, appxSet map[string]struct{}) error {
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

			routing := classifyForAppLocker(path, appxSet)

			// Build a standard FilePathRule string
			buildRule := func(namePrefix string, overridePath string) string {
				targetPath := path
				if overridePath != "" {
					targetPath = overridePath
				}
				return fmt.Sprintf(`
    <FilePathRule Id="%s" Name="KubeArmor Block %s %s" Description="KubeArmor Enforced" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="%s" />
      </Conditions>
    </FilePathRule>`, uuid.New().String(), namePrefix, baseName, targetPath)
			}

			if routing.Exe {
				exeRules.WriteString(buildRule("Exe", ""))
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
			if routing.Appx {
				// Use *\basename wildcard so it matches regardless of the versioned WindowsApps directory.
				appxRules.WriteString(buildRule("Packaged", `*\`+baseName))
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
