package enforcer

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

func allowedProcesses(secPolicy tp.SecurityPolicy, allowLines []string, allowCount int) ([]string, int, bool) {
	oldCount := allowCount

	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if path.OwnerOnly {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				allowLines = append(allowLines, line)
				allowCount++
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				allowLines = append(allowLines, line)
				allowCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				allowLines = append(allowLines, line)
				allowCount++
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				allowLines = append(allowLines, line)
				allowCount++
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				allowLines = append(allowLines, line)
				allowCount++
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				allowLines = append(allowLines, line)
				allowCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			if pat.OwnerOnly {
				line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
				allowLines = append(allowLines, line)
				allowCount++
			} else { // !pat.OwnerOnly
				line := fmt.Sprintf("  %s* ix,\n", pat.Pattern)
				allowLines = append(allowLines, line)
				allowCount++
			}
		}
	}

	return allowLines, allowCount, !(allowCount == oldCount)
}

func allowedFiles(secPolicy tp.SecurityPolicy, allowLines []string, allowCount int) ([]string, int, bool) {
	oldCount := allowCount

	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				allowLines = append(allowLines, line)
				allowCount++
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  %s r,\n", path.Path)
				allowLines = append(allowLines, line)
				allowCount++
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				allowLines = append(allowLines, line)
				allowCount++
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				allowLines = append(allowLines, line)
				allowCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					allowLines = append(allowLines, line)
					allowCount++
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					allowLines = append(allowLines, line)
					allowCount++
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					allowLines = append(allowLines, line)
					allowCount++
				} else {
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					allowLines = append(allowLines, line)
					allowCount++
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					allowLines = append(allowLines, line)
					allowCount++
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					allowLines = append(allowLines, line)
					allowCount++
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					allowLines = append(allowLines, line)
					allowCount++
				} else {
					line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
					allowLines = append(allowLines, line)
					allowCount++
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
				allowLines = append(allowLines, line)
				allowCount++
			} else if pat.ReadOnly && !pat.OwnerOnly {
				line := fmt.Sprintf("  %s r,\n", pat.Pattern)
				allowLines = append(allowLines, line)
				allowCount++
			} else if !pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
				allowLines = append(allowLines, line)
				allowCount++
			} else { // !pat.ReadOnly && !pat.OwnerOnly
				line := fmt.Sprintf("  %s rw,\n", pat.Pattern)
				allowLines = append(allowLines, line)
				allowCount++
			}
		}
	}

	return allowLines, allowCount, !(allowCount == oldCount)
}

func allowedNetworks(secPolicy tp.SecurityPolicy, allowLines []string, allowCount int) ([]string, int, bool) {
	oldCount := allowCount

	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for _, protocol := range secPolicy.Spec.Network.MatchProtocols {
			line := fmt.Sprintf("  network %s,\n", protocol)
			allowLines = append(allowLines, line)
			allowCount++
		}
	}

	return allowLines, allowCount, !(allowCount == oldCount)
}

func allowedCapabilities(secPolicy tp.SecurityPolicy, allowLines []string, allowCount int) ([]string, int, bool) {
	oldCount := allowCount

	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			line := fmt.Sprintf("  capability %s\n", cap)
			allowLines = append(allowLines, line)
			allowCount++
		}
	}

	return allowLines, allowCount, !(allowCount == oldCount)
}

//

func auditedProcesses(secPolicy tp.SecurityPolicy, auditLines []string, auditCount int) ([]string, int) {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			line := fmt.Sprintf("  audit %s ix,\n", path.Path)
			auditLines = append(auditLines, line)
			auditCount++
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.Recursive {
				line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
				auditLines = append(auditLines, line)
				auditCount++
			} else { // !dir.Recursive
				line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
				auditLines = append(auditLines, line)
				auditCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			line := fmt.Sprintf("  audit %s ix,\n", pat.Pattern)
			auditLines = append(auditLines, line)
			auditCount++
		}
	}

	return auditLines, auditCount
}

func auditedFiles(secPolicy tp.SecurityPolicy, auditLines []string, auditCount int) ([]string, int) {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if path.ReadOnly {
				line := fmt.Sprintf("  audit %s r,\n", path.Path)
				auditLines = append(auditLines, line)
				auditCount++
			} else { // !path.ReadOnly
				line := fmt.Sprintf("  audit %s rw,\n", path.Path)
				auditLines = append(auditLines, line)
				auditCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.ReadOnly && dir.Recursive {
				line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
				auditLines = append(auditLines, line)
				auditCount++
			} else if dir.ReadOnly && !dir.Recursive {
				line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
				auditLines = append(auditLines, line)
				auditCount++
			} else if !dir.ReadOnly && dir.Recursive {
				line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
				auditLines = append(auditLines, line)
				auditCount++
			} else { // !dir.ReadOnly && !dir.Recursive
				line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
				auditLines = append(auditLines, line)
				auditCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.ReadOnly {
				line := fmt.Sprintf("  audit %s r,\n", pat.Pattern)
				auditLines = append(auditLines, line)
				auditCount++
			} else { // !pat.ReadOnly
				line := fmt.Sprintf("  audit %s rw,\n", pat.Pattern)
				auditLines = append(auditLines, line)
				auditCount++
			}
		}
	}

	return auditLines, auditCount
}

//

func blockedProcesses(secPolicy tp.SecurityPolicy, denyLines []string, denyCount int) ([]string, int) {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
			denyLines = append(denyLines, line)
			denyCount++
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.Recursive {
				line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			} else { // !dir.Recursive
				line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			line := fmt.Sprintf("  audit deny %s x,\n", pat.Pattern)
			denyLines = append(denyLines, line)
			denyCount++
		}
	}

	return denyLines, denyCount
}

func blockedFiles(secPolicy tp.SecurityPolicy, denyLines []string, denyCount int) ([]string, int) {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if path.ReadOnly {
				line := fmt.Sprintf("  audit deny %s w,\n", path.Path)
				denyLines = append(denyLines, line)
				denyCount++
			} else { // !path.ReadOnly
				line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
				denyLines = append(denyLines, line)
				denyCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.ReadOnly && dir.Recursive {
				line := fmt.Sprintf("  audit deny %s{*,**} w,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			} else if dir.ReadOnly && !dir.Recursive {
				line := fmt.Sprintf("  audit deny %s* w,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			} else if !dir.ReadOnly && dir.Recursive {
				line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			} else { // !dir.ReadOnly && !dir.Recursive
				line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.ReadOnly {
				line := fmt.Sprintf("  audit deny %s w,\n", pat.Pattern)
				denyLines = append(denyLines, line)
				denyCount++
			} else { // !pat.ReadOnly
				line := fmt.Sprintf("  audit deny %s rw,\n", pat.Pattern)
				denyLines = append(denyLines, line)
				denyCount++
			}
		}
	}

	return denyLines, denyCount
}

func blockedNetworks(secPolicy tp.SecurityPolicy, denyLines []string, denyCount int) ([]string, int) {
	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for _, protocol := range secPolicy.Spec.Network.MatchProtocols {
			line := fmt.Sprintf("  deny network %s,\n", protocol)
			denyLines = append(denyLines, line)
			denyCount++
		}
	}

	return denyLines, denyCount
}

func blockedCapabilities(secPolicy tp.SecurityPolicy, denyLines []string, denyCount int) ([]string, int) {
	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			line := fmt.Sprintf("  deny capability %s,\n", cap)
			denyLines = append(denyLines, line)
			denyCount++
		}
	}

	return denyLines, denyCount
}

//

// GenerateAppArmorProfile Function
func GenerateAppArmorProfile(appArmorProfile string, securityPolicies []tp.SecurityPolicy) (int, string, bool) {
	// check apparmor profile

	if _, err := os.Stat("/etc/apparmor.d/" + appArmorProfile); os.IsNotExist(err) {
		return 0, err.Error(), false
	}

	// get the old profile

	oldProfile := ""

	oldContentsHead := []string{}
	oldContentsPreMid := []string{}
	oldConetntsMidPost := []string{}
	oldContentsFoot := []string{}

	file, err := os.Open("/etc/apparmor.d/" + appArmorProfile)
	if err != nil {
		return 0, err.Error(), false
	}

	fscanner := bufio.NewScanner(file)
	pos := "HEAD"

	for fscanner.Scan() {
		line := fscanner.Text()

		oldProfile += (line + "\n")

		if strings.Contains(line, "## == PRE START == ##") {
			pos = "PRE"
			continue
		} else if strings.Contains(line, "## == PRE END == ##") {
			pos = "PRE-MIDDLE"
			continue
		} else if strings.Contains(line, "## == POLICY START == ##") {
			pos = "POLICY"
			continue
		} else if strings.Contains(line, "## == POLICY END == ##") {
			pos = "MIDDLE-POST"
			continue
		} else if strings.Contains(line, "## == POST START == ##") {
			pos = "POST"
			continue
		} else if strings.Contains(line, "## == POST END == ##") {
			pos = "FOOT"
			continue
		}

		if pos == "HEAD" {
			oldContentsHead = append(oldContentsHead, line+"\n")
		} else if pos == "PRE" {
			//
		} else if pos == "PRE-MIDDLE" {
			oldContentsPreMid = append(oldContentsPreMid, line+"\n")
		} else if pos == "POLICY" {
			//
		} else if pos == "MIDDLE-POST" {
			oldConetntsMidPost = append(oldConetntsMidPost, line+"\n")
		} else if pos == "FOOT" {
			oldContentsFoot = append(oldContentsFoot, line+"\n")
		}
	}

	file.Close()

	// generate a new profile

	allowLines := []string{}
	allowCount := 0

	auditLines := []string{}
	auditCount := 0

	denyLines := []string{}
	denyCount := 0

	processWhiteList := false
	fileWhiteList := false
	networkWhiteList := false
	capabilitiesWhiteList := false

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Allow" || secPolicy.Spec.Action == "AllowWithAudit" {
			whiteList := false

			// process
			allowLines, allowCount, whiteList = allowedProcesses(secPolicy, allowLines, allowCount)
			if whiteList {
				processWhiteList = true
			}

			// file
			allowLines, allowCount, whiteList = allowedFiles(secPolicy, allowLines, allowCount)
			if whiteList {
				fileWhiteList = true
			}

			// network
			allowLines, allowCount, whiteList = allowedNetworks(secPolicy, allowLines, allowCount)
			if whiteList {
				networkWhiteList = true
			}

			// capabilities
			allowLines, allowCount, whiteList = allowedCapabilities(secPolicy, allowLines, allowCount)
			if whiteList {
				capabilitiesWhiteList = true
			}
		}
	}

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Audit" {
			// process
			auditLines, auditCount = auditedProcesses(secPolicy, auditLines, auditCount)

			// file
			auditLines, auditCount = auditedFiles(secPolicy, auditLines, auditCount)
		}
	}

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Block" {
			// process
			denyLines, denyCount = blockedProcesses(secPolicy, denyLines, denyCount)

			// file
			denyLines, denyCount = blockedFiles(secPolicy, denyLines, denyCount)

			// network
			denyLines, denyCount = blockedNetworks(secPolicy, denyLines, denyCount)

			// capabilities
			denyLines, denyCount = blockedCapabilities(secPolicy, denyLines, denyCount)
		}
	}

	newProfile := ""

	// head

	for _, head := range oldContentsHead {
		newProfile = newProfile + head
	}

	// pre

	newProfile = newProfile + "  ## == PRE START == ##\n"

	if !(processWhiteList || fileWhiteList) {
		newProfile = newProfile + "  file,\n"
	}

	if !networkWhiteList {
		newProfile = newProfile + "  network,\n"
	}

	if !capabilitiesWhiteList {
		newProfile = newProfile + "  capability,\n"
	}

	newProfile = newProfile + "  ## == PRE END == ##\n"

	// pre-middle

	for _, preMid := range oldContentsPreMid {
		newProfile = newProfile + preMid
	}

	// policy

	newProfile = newProfile + "  ## == POLICY START == ##\n"

	for _, line := range allowLines {
		newProfile = newProfile + line
	}

	for _, line := range denyLines {
		newProfile = newProfile + line
	}

	for _, line := range auditLines {
		newProfile = newProfile + line
	}

	// resource

	newProfile = newProfile + "  ## == POLICY END == ##\n"

	// middle-post

	for _, midPost := range oldConetntsMidPost {
		newProfile = newProfile + midPost
	}

	// post

	newProfile = newProfile + "  ## == POST START == ##\n"

	if processWhiteList || fileWhiteList {
		newProfile = newProfile + "  /bin/bash ix,\n"
		newProfile = newProfile + "  /lib/x86_64-linux-gnu/{*,**} r,\n"
	}

	newProfile = newProfile + "  ## == POST END == ##\n"

	// foot

	for _, foot := range oldContentsFoot {
		newProfile = newProfile + foot
	}

	if newProfile != oldProfile {
		return allowCount + auditCount + denyCount, newProfile, true
	}

	return 0, "", false
}
