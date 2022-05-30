// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

// ResolvedProcessWhiteListConflicts Function
func (ae *AppArmorEnforcer) ResolvedProcessWhiteListConflicts(processWhiteList *[]string, fromSources map[string][]string, fusionProcessWhiteList *[]string) {
	prunedProcessWhiteList := make([]string, len(*processWhiteList))
	copy(prunedProcessWhiteList, *processWhiteList)

	for source := range fromSources {
		for _, line := range *processWhiteList {
			if source == strings.Split(strings.TrimSpace(line), " ")[0] {
				if !kl.ContainsElement(*fusionProcessWhiteList, source) {
					*fusionProcessWhiteList = append(*fusionProcessWhiteList, source)

					for idx, line := range prunedProcessWhiteList {
						if source == strings.Split(strings.TrimSpace(line), " ")[0] {
							prunedProcessWhiteList = append(prunedProcessWhiteList[:idx], prunedProcessWhiteList[idx+1:]...)
							break
						}
					}
				}
			}
		}
	}

	*processWhiteList = prunedProcessWhiteList
}

// AllowedProcessMatchPaths Function
func (ae *AppArmorEnforcer) AllowedProcessMatchPaths(path tp.ProcessPathType, processWhiteList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		line := ""

		if path.OwnerOnly {
			line = fmt.Sprintf("  owner %s ix,\n", path.Path)
		} else { // !path.OwnerOnly
			line = fmt.Sprintf("  %s ix,\n", path.Path)
		}

		if !kl.ContainsElement(*processWhiteList, line) {
			*processWhiteList = append(*processWhiteList, line)
		}

		return
	}

	for _, src := range path.FromSource {
		line := ""

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		if path.OwnerOnly {
			line = fmt.Sprintf("  owner %s ix,\n", path.Path)
		} else { // !path.OwnerOnly
			line = fmt.Sprintf("  %s ix,\n", path.Path)
		}

		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// AllowedProcessMatchDirectories Function
func (ae *AppArmorEnforcer) AllowedProcessMatchDirectories(dir tp.ProcessDirectoryType, processWhiteList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		line := ""

		if dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
		} else if dir.Recursive && !dir.OwnerOnly {
			line = fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
		} else if !dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
		} else { // !dir.Recursive && !dir.OwnerOnly
			line = fmt.Sprintf("  %s* ix,\n", dir.Directory)
		}

		if !kl.ContainsElement(*processWhiteList, line) {
			*processWhiteList = append(*processWhiteList, line)
		}

		return
	}

	for _, src := range dir.FromSource {
		line := ""

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		if dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
		} else if dir.Recursive && !dir.OwnerOnly {
			line = fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
		} else if !dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
		} else { // !dir.Recursive && !dir.OwnerOnly
			line = fmt.Sprintf("  %s* ix,\n", dir.Directory)
		}

		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// AllowedProcessMatchPatterns Function
func (ae *AppArmorEnforcer) AllowedProcessMatchPatterns(pat tp.ProcessPatternType, processWhiteList *[]string) {
	line := ""

	if pat.OwnerOnly {
		line = fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
	} else { // !pat.OwnerOnly
		line = fmt.Sprintf("  %s* ix,\n", pat.Pattern)
	}

	if !kl.ContainsElement(*processWhiteList, line) {
		*processWhiteList = append(*processWhiteList, line)
	}
}

// AllowedFileMatchPaths Function
func (ae *AppArmorEnforcer) AllowedFileMatchPaths(path tp.FilePathType, fileWhiteList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		line := ""

		if path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  owner %s r,\n", path.Path)
		} else if path.ReadOnly && !path.OwnerOnly {
			line = fmt.Sprintf("  %s r,\n", path.Path)
		} else if !path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  owner %s rw,\n", path.Path)
		} else { // !path.ReadOnly && !path.OwnerOnly
			line = fmt.Sprintf("  %s rw,\n", path.Path)
		}

		if !kl.ContainsElement(*fileWhiteList, line) {
			*fileWhiteList = append(*fileWhiteList, line)
		}

		return
	}

	for _, src := range path.FromSource {
		line := ""

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		if path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  owner %s r,\n", path.Path)
		} else if path.ReadOnly && !path.OwnerOnly {
			line = fmt.Sprintf("  %s r,\n", path.Path)
		} else if !path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  owner %s rw,\n", path.Path)
		} else { // !path.ReadOnly && !path.OwnerOnly
			line = fmt.Sprintf("  %s rw,\n", path.Path)
		}

		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// AllowedFileMatchDirectories Function
func (ae *AppArmorEnforcer) AllowedFileMatchDirectories(dir tp.FileDirectoryType, fileWhiteList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		line := ""

		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  owner %s* r,\n", dir.Directory)
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  %s* r,\n", dir.Directory)
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				line = fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  %s* rw,\n", dir.Directory)
			}
		}

		if !kl.ContainsElement(*fileWhiteList, line) {
			*fileWhiteList = append(*fileWhiteList, line)
		}

		return
	}

	for _, src := range dir.FromSource {
		line := ""

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  owner %s* r,\n", dir.Directory)
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  %s* r,\n", dir.Directory)
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				line = fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  %s* rw,\n", dir.Directory)
			}
		}

		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// AllowedFileMatchPatterns Function
func (ae *AppArmorEnforcer) AllowedFileMatchPatterns(pat tp.FilePatternType, fileWhiteList *[]string) {
	line := ""

	if pat.ReadOnly && pat.OwnerOnly {
		line = fmt.Sprintf("  owner %s r,\n", pat.Pattern)
	} else if pat.ReadOnly && !pat.OwnerOnly {
		line = fmt.Sprintf("  %s r,\n", pat.Pattern)
	} else if !pat.ReadOnly && pat.OwnerOnly {
		line = fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		line = fmt.Sprintf("  %s rw,\n", pat.Pattern)
	}

	if !kl.ContainsElement(*fileWhiteList, line) {
		*fileWhiteList = append(*fileWhiteList, line)
	}
}

// AllowedNetworkMatchProtocols Function
func (ae *AppArmorEnforcer) AllowedNetworkMatchProtocols(proto tp.NetworkProtocolType, networkWhiteList *[]string, fromSources map[string][]string) {
	if len(proto.FromSource) == 0 {
		line := fmt.Sprintf("  network %s,\n", proto.Protocol)
		if !kl.ContainsElement(*networkWhiteList, line) {
			*networkWhiteList = append(*networkWhiteList, line)
		}
		return
	}

	for _, src := range proto.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		line := fmt.Sprintf("  network %s,\n", proto.Protocol)
		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// AllowedCapabilitiesMatchCapabilities Function
func (ae *AppArmorEnforcer) AllowedCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, capabilityWhiteList *[]string, fromSources map[string][]string) {
	if len(cap.FromSource) == 0 {
		line := fmt.Sprintf("  capability %s,\n", cap.Capability)
		if !kl.ContainsElement(*capabilityWhiteList, line) {
			*capabilityWhiteList = append(*capabilityWhiteList, line)
		}
		return
	}

	for _, src := range cap.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		line := fmt.Sprintf("  capability %s,\n", cap.Capability)
		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

//

// BlockedProcessMatchPaths Function
func (ae *AppArmorEnforcer) BlockedProcessMatchPaths(path tp.ProcessPathType, processBlackList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		line := ""

		if path.OwnerOnly {
			line = fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", path.Path, path.Path)
		} else { // !path.OwnerOnly
			line = fmt.Sprintf("  deny %s x,\n", path.Path)
		}

		if !kl.ContainsElement(*processBlackList, line) {
			*processBlackList = append(*processBlackList, line)
		}

		return
	}

	for _, src := range path.FromSource {
		line := ""

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		if path.OwnerOnly {
			line = fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", path.Path, path.Path)
		} else { // !path.OwnerOnly
			line = fmt.Sprintf("  deny %s x,\n", path.Path)
		}

		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// BlockedProcessMatchDirectories Function
func (ae *AppArmorEnforcer) BlockedProcessMatchDirectories(dir tp.ProcessDirectoryType, processBlackList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		line := ""

		if dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s{*,**} ix,\n  deny other %s{*,**} x,\n", dir.Directory, dir.Directory)
		} else if dir.Recursive && !dir.OwnerOnly {
			line = fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
		} else if !dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s* ix,\n  deny other %s* x,\n", dir.Directory, dir.Directory)
		} else { // !dir.Recursive && !dir.OwnerOnly
			line = fmt.Sprintf("  deny %s* x,\n", dir.Directory)
		}

		if !kl.ContainsElement(*processBlackList, line) {
			*processBlackList = append(*processBlackList, line)
		}

		return
	}

	for _, src := range dir.FromSource {
		line := ""

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		if dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s{*,**} ix,\n  deny other %s{*,**} x,\n", dir.Directory, dir.Directory)
		} else if dir.Recursive && !dir.OwnerOnly {
			line = fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
		} else if !dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s* ix,\n  deny other %s* x,\n", dir.Directory, dir.Directory)
		} else { // !dir.Recursive && !dir.OwnerOnly
			line = fmt.Sprintf("  deny %s* x,\n", dir.Directory)
		}

		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// BlockedProcessMatchPatterns Function
func (ae *AppArmorEnforcer) BlockedProcessMatchPatterns(pat tp.ProcessPatternType, processBlackList *[]string) {
	line := ""

	if pat.OwnerOnly {
		line = fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", pat.Pattern, pat.Pattern)
	} else { // !path.OwnerOnly
		line = fmt.Sprintf("  deny %s x,\n", pat.Pattern)
	}

	if !kl.ContainsElement(*processBlackList, line) {
		*processBlackList = append(*processBlackList, line)
	}
}

// BlockedFileMatchPaths Function
func (ae *AppArmorEnforcer) BlockedFileMatchPaths(path tp.FilePathType, fileBlackList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		line := ""

		if path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  deny owner %s w,\n  deny other %s rw,\n", path.Path, path.Path)
		} else if path.ReadOnly && !path.OwnerOnly {
			line = fmt.Sprintf("  deny %s w,\n", path.Path)
		} else if !path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  owner %s rw,\n  deny other %s rw,\n", path.Path, path.Path)
		} else { // !path.ReadOnly && !path.OwnerOnly
			line = fmt.Sprintf("  deny %s rw,\n", path.Path)
		}

		if !kl.ContainsElement(*fileBlackList, line) {
			*fileBlackList = append(*fileBlackList, line)
		}

		return
	}

	for _, src := range path.FromSource {
		line := ""

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		if path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  deny owner %s w,\n  deny other %s rw,\n", path.Path, path.Path)
		} else if path.ReadOnly && !path.OwnerOnly {
			line = fmt.Sprintf("  deny %s w,\n", path.Path)
		} else if !path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  owner %s rw,\n  deny other %s rw,\n", path.Path, path.Path)
		} else { // !path.ReadOnly && !path.OwnerOnly
			line = fmt.Sprintf("  deny %s rw,\n", path.Path)
		}

		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// BlockedFileMatchDirectories Function
func (ae *AppArmorEnforcer) BlockedFileMatchDirectories(dir tp.FileDirectoryType, fileBlackList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		line := ""

		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  deny owner %s{*,**} w,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
			} else {
				line = fmt.Sprintf("  deny owner %s* w,\n  deny other %s* rw,\n", dir.Directory, dir.Directory)
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  deny %s* w,\n", dir.Directory)
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  owner %s{*,**} rw,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
			} else {
				line = fmt.Sprintf("  owner %s* rw,\n  deny other %s* w,\n", dir.Directory, dir.Directory)
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				line = fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  deny %s* rw,\n", dir.Directory)
			}
		}

		if !kl.ContainsElement(*fileBlackList, line) {
			*fileBlackList = append(*fileBlackList, line)
		}

		return
	}

	for _, src := range dir.FromSource {
		line := ""

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  deny owner %s{*,**} w,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
			} else {
				line = fmt.Sprintf("  deny owner %s* w,\n  deny other %s* rw,\n", dir.Directory, dir.Directory)
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  deny %s* w,\n", dir.Directory)
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line = fmt.Sprintf("  owner %s{*,**} rw,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
			} else {
				line = fmt.Sprintf("  owner %s* rw,\n  deny other %s* w,\n", dir.Directory, dir.Directory)
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				line = fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
			} else {
				line = fmt.Sprintf("  deny %s* rw,\n", dir.Directory)
			}
		}

		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// BlockedFileMatchPatterns Function
func (ae *AppArmorEnforcer) BlockedFileMatchPatterns(pat tp.FilePatternType, fileBlackList *[]string) {
	line := ""

	if pat.ReadOnly && pat.OwnerOnly {
		line = fmt.Sprintf("  deny owner %s w,\n  deny other %s rw,\n", pat.Pattern, pat.Pattern)
	} else if pat.ReadOnly && !pat.OwnerOnly {
		line = fmt.Sprintf("  deny %s w,\n", pat.Pattern)
	} else if !pat.ReadOnly && pat.OwnerOnly {
		line = fmt.Sprintf("  owner %s rw,\n  deny other %s rw,\n", pat.Pattern, pat.Pattern)
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		line = fmt.Sprintf("  deny %s rw,\n", pat.Pattern)
	}

	if !kl.ContainsElement(*fileBlackList, line) {
		*fileBlackList = append(*fileBlackList, line)
	}
}

// BlockedNetworkMatchProtocols Function
func (ae *AppArmorEnforcer) BlockedNetworkMatchProtocols(proto tp.NetworkProtocolType, networkBlackList *[]string, fromSources map[string][]string) {
	if len(proto.FromSource) == 0 {
		line := fmt.Sprintf("  deny network %s,\n", proto.Protocol)
		if !kl.ContainsElement(*networkBlackList, line) {
			*networkBlackList = append(*networkBlackList, line)
		}
		return
	}

	for _, src := range proto.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		line := fmt.Sprintf("  deny network %s,\n", proto.Protocol)
		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// BlockedCapabilitiesMatchCapabilities Function
func (ae *AppArmorEnforcer) BlockedCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, capabilityBlackList *[]string, fromSources map[string][]string) {
	if len(cap.FromSource) == 0 {
		line := fmt.Sprintf("  deny capability %s,\n", cap.Capability)
		if !kl.ContainsElement(*capabilityBlackList, line) {
			*capabilityBlackList = append(*capabilityBlackList, line)
		}
		return
	}

	for _, src := range cap.FromSource {
		if len(src.Path) <= 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []string{}
		}

		line := fmt.Sprintf("  deny capability %s,\n", cap.Capability)
		if !kl.ContainsElement(fromSources[source], line) {
			fromSources[source] = append(fromSources[source], line)
		}
	}
}

// == //

// GenerateProfileHead Function
func (ae *AppArmorEnforcer) GenerateProfileHead(numProcessWhiteList, numFileWhiteList, numNetworkWhiteList, numCapabilityWhiteList int, fromSourceFile, fromSourceNetwork, fromSourceCapability bool, defaultPosture tp.DefaultPosture) string {
	profileHead := "  #include <abstractions/base>\n"
	profileHead = profileHead + "  umount,\n"

	// Allow Access to Resource when
	// -> Default Posture is not Block
	// OR
	// -> No allow policy AND No from source allow policy

	if !(defaultPosture.FileAction == "block") || !(numProcessWhiteList > 0 || numFileWhiteList > 0 || !fromSourceFile) {
		profileHead = profileHead + "  file,\n"
	}

	if !(defaultPosture.NetworkAction == "block") || !(numNetworkWhiteList > 0 || !fromSourceNetwork) {
		profileHead = profileHead + "  network,\n"
	}

	if !(defaultPosture.CapabilitiesAction == "block") || !(numCapabilityWhiteList > 0 || !fromSourceCapability) {
		profileHead = profileHead + "  capability,\n"
	}

	return profileHead
}

// GenerateProfileFoot Function
func (ae *AppArmorEnforcer) GenerateProfileFoot() string {
	profileFoot := "  /lib/x86_64-linux-gnu/{*,**} rm,\n"
	profileFoot = profileFoot + "\n"
	profileFoot = profileFoot + "  deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,\n"
	profileFoot = profileFoot + "  deny @{PROC}/sysrq-trigger rwklx,\n"
	profileFoot = profileFoot + "  deny @{PROC}/mem rwklx,\n"
	profileFoot = profileFoot + "  deny @{PROC}/kmem rwklx,\n"
	profileFoot = profileFoot + "  deny @{PROC}/kcore rwklx,\n"
	profileFoot = profileFoot + "\n"
	profileFoot = profileFoot + "  deny mount,\n"
	profileFoot = profileFoot + "\n"
	profileFoot = profileFoot + "  deny /sys/[^f]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/f[^s]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/fs/[^c]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/fs/c[^g]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/fs/cg[^r]*/** wklx,\n"
	profileFoot = profileFoot + "  deny /sys/firmware/efi/efivars/** rwklx,\n"
	profileFoot = profileFoot + "  deny /sys/kernel/security/** rwklx,\n"

	return profileFoot
}

// == //

// GenerateProfileBody Function
func (ae *AppArmorEnforcer) GenerateProfileBody(securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) (int, string) {
	// preparation

	count := 0

	processWhiteList := []string{}
	processBlackList := []string{}

	fileWhiteList := []string{}
	fileBlackList := []string{}

	networkWhiteList := []string{}
	networkBlackList := []string{}

	capabilityWhiteList := []string{}
	capabilityBlackList := []string{}

	fromSources := map[string][]string{}

	nativeAppArmorRules := []string{}

	fusionProcessWhiteList := []string{}

	fromSourceFile := true
	fromSourceNetwork := true
	fromSourceCapability := true

	// preparation

	for _, secPolicy := range securityPolicies {
		if len(secPolicy.Spec.AppArmor) > 0 {
			scanner := bufio.NewScanner(strings.NewReader(secPolicy.Spec.AppArmor))
			for scanner.Scan() {
				line := "  " + strings.TrimSpace(scanner.Text()) + "\n"
				nativeAppArmorRules = append(nativeAppArmorRules, line)
			}
		}

		if len(secPolicy.Spec.Process.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.Process.MatchPaths {
				if path.Action == "Allow" {
					ae.AllowedProcessMatchPaths(path, &processWhiteList, fromSources)
				} else if path.Action == "Block" {
					ae.BlockedProcessMatchPaths(path, &processBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" {
					ae.AllowedProcessMatchDirectories(dir, &processWhiteList, fromSources)
				} else if dir.Action == "Block" {
					ae.BlockedProcessMatchDirectories(dir, &processBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.Process.MatchPatterns {
				if pat.Action == "Allow" {
					ae.AllowedProcessMatchPatterns(pat, &processWhiteList)
				} else if pat.Action == "Block" {
					ae.BlockedProcessMatchPatterns(pat, &processBlackList)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" {
					ae.AllowedFileMatchPaths(path, &fileWhiteList, fromSources)
				} else if path.Action == "Block" {
					ae.BlockedFileMatchPaths(path, &fileBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" {
					ae.AllowedFileMatchDirectories(dir, &fileWhiteList, fromSources)
				} else if dir.Action == "Block" {
					ae.BlockedFileMatchDirectories(dir, &fileBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.File.MatchPatterns {
				if pat.Action == "Allow" {
					ae.AllowedFileMatchPatterns(pat, &fileWhiteList)
				} else if pat.Action == "Block" {
					ae.BlockedFileMatchPatterns(pat, &fileBlackList)
				}
			}
		}

		if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
			for _, proto := range secPolicy.Spec.Network.MatchProtocols {
				if proto.Action == "Allow" {
					ae.AllowedNetworkMatchProtocols(proto, &networkWhiteList, fromSources)
				} else if proto.Action == "Block" {
					ae.BlockedNetworkMatchProtocols(proto, &networkBlackList, fromSources)
				}
			}
		}

		if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
			for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
				if cap.Action == "Allow" {
					ae.AllowedCapabilitiesMatchCapabilities(cap, &capabilityWhiteList, fromSources)
				} else if cap.Action == "Block" {
					ae.BlockedCapabilitiesMatchCapabilities(cap, &capabilityBlackList, fromSources)
				}
			}
		}
	}

	// Count the number of global security rules

	numProcessWhiteList := len(processWhiteList)
	numFileWhiteList := len(fileWhiteList)
	numNetworkWhiteList := len(networkWhiteList)
	numCapabilityWhiteList := len(capabilityWhiteList)

	count = count + numProcessWhiteList + numFileWhiteList + numNetworkWhiteList + numCapabilityWhiteList

	// Resolve conflicts
	ae.ResolvedProcessWhiteListConflicts(&processWhiteList, fromSources, &fusionProcessWhiteList)

	// body

	profileBody := ""

	// body - white list

	for _, line := range processWhiteList {
		profileBody = profileBody + line
	}

	for _, line := range fileWhiteList {
		profileBody = profileBody + line
	}

	for _, line := range networkWhiteList {
		profileBody = profileBody + line
	}

	for _, line := range capabilityWhiteList {
		profileBody = profileBody + line
	}

	// body - black list

	for _, line := range processBlackList {
		profileBody = profileBody + line
	}

	for _, line := range fileBlackList {
		profileBody = profileBody + line
	}

	for _, line := range networkBlackList {
		profileBody = profileBody + line
	}

	for _, line := range capabilityBlackList {
		profileBody = profileBody + line
	}

	// body - from source

	bodyFromSource := ""

	for source, lines := range fromSources {
		if kl.ContainsElement(fusionProcessWhiteList, source) {
			bodyFromSource = bodyFromSource + fmt.Sprintf("  %s cix,\n", source)
		} else {
			bodyFromSource = bodyFromSource + fmt.Sprintf("  %s cx,\n", source)
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("  profile %s {\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("    %s rix,\n", source)

		// head

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == PRE START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + "    #include <abstractions/base>\n"
		bodyFromSource = bodyFromSource + "    umount,\n"

		file := true
		network := true
		capability := true

		for _, line := range lines {
			if strings.Contains(line, "  network") {
				network = false
				fromSourceNetwork = false
				continue
			}

			if strings.Contains(line, "  capability") {
				capability = false
				fromSourceCapability = false
				continue
			}

			if strings.Contains(line, "  owner") && strings.Contains(line, "deny") {
				continue
			}

			if strings.Contains(line, "  deny") {
				continue
			}

			file = false
			fromSourceFile = false
		}

		if !(defaultPosture.FileAction == "block") || !(numProcessWhiteList > 0 || numFileWhiteList > 0 || !file) {
			bodyFromSource = bodyFromSource + "    file,\n"
		}

		if !(defaultPosture.NetworkAction == "block") || !(numNetworkWhiteList > 0 || !network) {
			bodyFromSource = bodyFromSource + "    network,\n"
		}

		if !(defaultPosture.CapabilitiesAction == "block") || !(numCapabilityWhiteList > 0 || !capability) {
			bodyFromSource = bodyFromSource + "    capability,\n"
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == PRE END (%s) == ##\n\n", source)

		// body

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + strings.Replace(profileBody, "  ", "    ", -1)

		for _, line := range lines {
			bodyFromSource = bodyFromSource + "  " + line
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY END (%s) == ##\n\n", source)

		// foot

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POST START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + strings.Replace(ae.GenerateProfileFoot(), "  ", "    ", -1)

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POST END (%s) == ##\n", source)
		bodyFromSource = bodyFromSource + "  }\n"
	}

	for _, source := range fromSources {
		count = count + len(source)
	}

	// head

	profileHead := "  ## == PRE START == ##\n" + ae.GenerateProfileHead(numProcessWhiteList, numFileWhiteList, numNetworkWhiteList, numCapabilityWhiteList, fromSourceFile, fromSourceNetwork, fromSourceCapability, defaultPosture) + "  ## == PRE END == ##\n\n"

	// body - together

	profileBody = "  ## == POLICY START == ##\n" + profileBody + bodyFromSource + "  ## == POLICY END == ##\n\n"

	// body - native apparmor

	if len(nativeAppArmorRules) > 0 {
		profileBody = profileBody + "\n  ## == NATIVE POLICY START == ##\n"
		for _, nativeRule := range nativeAppArmorRules {
			profileBody = profileBody + nativeRule
		}
		profileBody = profileBody + "  ## == NATIVE POLICY END == ##\n\n"
	}

	count = count + len(nativeAppArmorRules)

	// foot

	profileFoot := "  ## == POST START == ##\n" + ae.GenerateProfileFoot() + "  ## == POST END == ##\n"

	// finalization

	return count, profileHead + profileBody + profileFoot
}

// == //

// GenerateAppArmorProfile Function
func (ae *AppArmorEnforcer) GenerateAppArmorProfile(appArmorProfile string, securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) (int, string, bool) {
	// check apparmor profile

	if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + appArmorProfile)); os.IsNotExist(err) {
		return 0, err.Error(), false
	}

	// get the old profile

	profile, err := ioutil.ReadFile(filepath.Clean("/etc/apparmor.d/" + appArmorProfile))
	if err != nil {
		return 0, err.Error(), false
	}
	oldProfile := string(profile)

	// generate a profile body

	count, newProfileBody := ae.GenerateProfileBody(securityPolicies, defaultPosture)

	newProfile := "## == Managed by KubeArmor == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile " + appArmorProfile + " flags=(attach_disconnected,mediate_deleted) {\n" +
		newProfileBody +
		"}\n"

	// check the new profile with the old profile

	if newProfile != oldProfile {
		return count, newProfile, true
	}

	return 0, "", false
}
