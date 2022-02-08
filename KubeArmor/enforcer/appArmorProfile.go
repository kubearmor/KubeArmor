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
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

// ResolvedProcessWhiteListConflicts Function
func (ae *AppArmorEnforcer) ResolvedProcessWhiteListConflicts(processWhiteList *[]string, fromSources map[string][]string, fusionProcessWhiteList *[]string) {
	prunedProcessWhiteList := make([]string, len(*processWhiteList))
	copy(prunedProcessWhiteList, *processWhiteList)
	numOfRemovedElements := 0

	for index, line := range *processWhiteList {
		for source := range fromSources {
			if strings.Contains(line, source) {
				*fusionProcessWhiteList = append(*fusionProcessWhiteList, source)

				// remove line from WhiteList
				prunedProcessWhiteList = kl.RemoveStringElement(prunedProcessWhiteList, index-numOfRemovedElements)
				numOfRemovedElements = numOfRemovedElements + 1
			}
		}
	}

	*processWhiteList = prunedProcessWhiteList
}

// AllowedProcessMatchPaths Function
func (ae *AppArmorEnforcer) AllowedProcessMatchPaths(path tp.ProcessPathType, processWhiteList *[]string, fromSources map[string][]string) {
	var line string
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			line = fmt.Sprintf("  owner %s ix,\n", path.Path)
		} else { // !path.OwnerOnly
			line = fmt.Sprintf("  %s ix,\n", path.Path)
		}
		if !kl.ContainsElement(*processWhiteList, line) {
			*processWhiteList = append(*processWhiteList, line)
		}
	} else {
		for _, src := range path.FromSource {
			if len(src.Path) <= 0 {
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
}

// AllowedProcessMatchDirectories Function
func (ae *AppArmorEnforcer) AllowedProcessMatchDirectories(dir tp.ProcessDirectoryType, processWhiteList *[]string, fromSources map[string][]string) {
	var line string
	if len(dir.FromSource) == 0 {
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
	} else {
		for _, src := range dir.FromSource {
			if len(src.Path) <= 0 {
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
}

// AllowedProcessMatchPatterns Function
func (ae *AppArmorEnforcer) AllowedProcessMatchPatterns(pat tp.ProcessPatternType, processWhiteList *[]string) {
	var line string
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
	var line string
	if len(path.FromSource) == 0 {
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
	} else {
		for _, src := range path.FromSource {
			if len(src.Path) <= 0 {
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
}

// AllowedFileMatchDirectories Function
func (ae *AppArmorEnforcer) AllowedFileMatchDirectories(dir tp.FileDirectoryType, fileWhiteList *[]string, fromSources map[string][]string) {
	var line string
	if len(dir.FromSource) == 0 {
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
	} else {
		for _, src := range dir.FromSource {
			if len(src.Path) <= 0 {
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
}

// AllowedFileMatchPatterns Function
func (ae *AppArmorEnforcer) AllowedFileMatchPatterns(pat tp.FilePatternType, fileWhiteList *[]string) {
	var line string
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
	} else {
		for _, src := range proto.FromSource {
			if len(src.Path) <= 0 {
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
}

// AllowedCapabilitiesMatchCapabilities Function
func (ae *AppArmorEnforcer) AllowedCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, capabilityWhiteList *[]string, fromSources map[string][]string) {
	if len(cap.FromSource) == 0 {
		line := fmt.Sprintf("  capability %s,\n", cap.Capability)
		if !kl.ContainsElement(*capabilityWhiteList, line) {
			*capabilityWhiteList = append(*capabilityWhiteList, line)
		}
	} else {
		for _, src := range cap.FromSource {
			if len(src.Path) <= 0 {
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
}

//

// AuditedProcessMatchPaths Function
func (ae *AppArmorEnforcer) AuditedProcessMatchPaths(path tp.ProcessPathType, processAuditList *[]string, fromSources map[string][]string) {
	var line string
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			line = fmt.Sprintf("  owner %s ix,\n", path.Path)
		} else { // !path.OwnerOnly
			line = fmt.Sprintf("  %s ix,\n", path.Path)
		}
		if !kl.ContainsElement(*processAuditList, line) {
			*processAuditList = append(*processAuditList, line)
		}
	} else {
		for _, src := range path.FromSource {
			if len(src.Path) <= 0 {
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
}

// AuditedProcessMatchDirectories Function
func (ae *AppArmorEnforcer) AuditedProcessMatchDirectories(dir tp.ProcessDirectoryType, processAuditList *[]string, fromSources map[string][]string) {
	var line string
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
		} else if dir.Recursive && !dir.OwnerOnly {
			line = fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
		} else if !dir.Recursive && dir.OwnerOnly {
			line = fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
		} else { // !dir.Recursive && !dir.OwnerOnly
			line = fmt.Sprintf("  %s* ix,\n", dir.Directory)
		}
		if !kl.ContainsElement(*processAuditList, line) {
			*processAuditList = append(*processAuditList, line)
		}
	} else {
		for _, src := range dir.FromSource {
			if len(src.Path) <= 0 {
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
}

// AuditedProcessMatchPatterns Function
func (ae *AppArmorEnforcer) AuditedProcessMatchPatterns(pat tp.ProcessPatternType, processAuditList *[]string) {
	var line string
	if pat.OwnerOnly {
		line = fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
	} else { // !pat.OwnerOnly
		line = fmt.Sprintf("  %s* ix,\n", pat.Pattern)
	}
	if !kl.ContainsElement(*processAuditList, line) {
		*processAuditList = append(*processAuditList, line)
	}
}

// AuditedFileMatchPaths Function
func (ae *AppArmorEnforcer) AuditedFileMatchPaths(path tp.FilePathType, fileAuditList *[]string, fromSources map[string][]string) {
	var line string
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  owner %s r,\n", path.Path)
		} else if path.ReadOnly && !path.OwnerOnly {
			line = fmt.Sprintf("  %s r,\n", path.Path)
		} else if !path.ReadOnly && path.OwnerOnly {
			line = fmt.Sprintf("  owner %s rw,\n", path.Path)
		} else { // !path.ReadOnly && !path.OwnerOnly
			line = fmt.Sprintf("  %s rw,\n", path.Path)
		}
		if !kl.ContainsElement(*fileAuditList, line) {
			*fileAuditList = append(*fileAuditList, line)
		}
	} else {
		for _, src := range path.FromSource {
			if len(src.Path) <= 0 {
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
}

// AuditedFileMatchDirectories Function
func (ae *AppArmorEnforcer) AuditedFileMatchDirectories(dir tp.FileDirectoryType, fileAuditList *[]string, fromSources map[string][]string) {
	var line string
	if len(dir.FromSource) == 0 {
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
		if !kl.ContainsElement(*fileAuditList, line) {
			*fileAuditList = append(*fileAuditList, line)
		}
	} else {
		for _, src := range dir.FromSource {
			if len(src.Path) <= 0 {
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
}

// AuditedFileMatchPatterns Function
func (ae *AppArmorEnforcer) AuditedFileMatchPatterns(pat tp.FilePatternType, fileAuditList *[]string) {
	var line string
	if pat.ReadOnly && pat.OwnerOnly {
		line = fmt.Sprintf("  owner %s r,\n", pat.Pattern)
	} else if pat.ReadOnly && !pat.OwnerOnly {
		line = fmt.Sprintf("  %s r,\n", pat.Pattern)
	} else if !pat.ReadOnly && pat.OwnerOnly {
		line = fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		line = fmt.Sprintf("  %s rw,\n", pat.Pattern)
	}
	if !kl.ContainsElement(*fileAuditList, line) {
		*fileAuditList = append(*fileAuditList, line)
	}
}

//

// BlockedProcessMatchPaths Function
func (ae *AppArmorEnforcer) BlockedProcessMatchPaths(path tp.ProcessPathType, processBlackList *[]string, fromSources map[string][]string) {
	var line string
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			line = fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", path.Path, path.Path)
		} else { // !path.OwnerOnly
			line = fmt.Sprintf("  deny %s x,\n", path.Path)
		}
		if !kl.ContainsElement(*processBlackList, line) {
			*processBlackList = append(*processBlackList, line)
		}
	} else {
		for _, src := range path.FromSource {
			if len(src.Path) <= 0 {
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
}

// BlockedProcessMatchDirectories Function
func (ae *AppArmorEnforcer) BlockedProcessMatchDirectories(dir tp.ProcessDirectoryType, processBlackList *[]string, fromSources map[string][]string) {
	var line string
	if len(dir.FromSource) == 0 {
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
	} else {
		for _, src := range dir.FromSource {
			if len(src.Path) <= 0 {
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
}

// BlockedProcessMatchPatterns Function
func (ae *AppArmorEnforcer) BlockedProcessMatchPatterns(pat tp.ProcessPatternType, processBlackList *[]string) {
	var line string
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
	var line string
	if len(path.FromSource) == 0 {
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
	} else {
		for _, src := range path.FromSource {
			if len(src.Path) <= 0 {
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
}

// BlockedFileMatchDirectories Function
func (ae *AppArmorEnforcer) BlockedFileMatchDirectories(dir tp.FileDirectoryType, fileBlackList *[]string, fromSources map[string][]string) {
	var line string
	if len(dir.FromSource) == 0 {
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
	} else {
		for _, src := range dir.FromSource {
			if len(src.Path) <= 0 {
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
}

// BlockedFileMatchPatterns Function
func (ae *AppArmorEnforcer) BlockedFileMatchPatterns(pat tp.FilePatternType, fileBlackList *[]string) {
	var line string
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
		if len(src.Path) <= 0 {
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
	} else {
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
}

// == //

// GenerateProfileHead Function
func (ae *AppArmorEnforcer) GenerateProfileHead(processWhiteList, fileWhiteList, networkWhiteList, capabilityWhiteList []string) string {
	profileHead := "  #include <abstractions/base>\n"
	profileHead = profileHead + "  umount,\n"

	if len(processWhiteList) == 0 && len(fileWhiteList) == 0 && cfg.GlobalCfg.DefaultFilePosture != "block" {
		profileHead = profileHead + "  file,\n"
	}

	if len(networkWhiteList) == 0 && cfg.GlobalCfg.DefaultNetworkPosture != "block" {
		profileHead = profileHead + "  network,\n"
	}

	if len(capabilityWhiteList) == 0 && cfg.GlobalCfg.DefaultCapabilitiesPosture != "block" {
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
func (ae *AppArmorEnforcer) GenerateProfileBody(securityPolicies []tp.SecurityPolicy) (int, string) {
	// preparation

	count := 0

	processWhiteList := []string{}
	processAuditList := []string{}
	processBlackList := []string{}

	fileWhiteList := []string{}
	fileAuditList := []string{}
	fileBlackList := []string{}

	networkWhiteList := []string{}
	networkBlackList := []string{}

	capabilityWhiteList := []string{}
	capabilityBlackList := []string{}

	fromSources := map[string][]string{}

	nativeAppArmorRules := []string{}

	fusionProcessWhiteList := []string{}

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
				} else if path.Action == "Audit" {
					ae.AuditedProcessMatchPaths(path, &processAuditList, fromSources)
				} else if path.Action == "Block" {
					ae.BlockedProcessMatchPaths(path, &processBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" {
					ae.AllowedProcessMatchDirectories(dir, &processWhiteList, fromSources)
				} else if dir.Action == "Audit" {
					ae.AuditedProcessMatchDirectories(dir, &processAuditList, fromSources)
				} else if dir.Action == "Block" {
					ae.BlockedProcessMatchDirectories(dir, &processBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.Process.MatchPatterns {
				if pat.Action == "Allow" {
					ae.AllowedProcessMatchPatterns(pat, &processWhiteList)
				} else if pat.Action == "Audit" {
					ae.AuditedProcessMatchPatterns(pat, &processAuditList)
				} else if pat.Action == "Block" {
					ae.BlockedProcessMatchPatterns(pat, &processBlackList)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" {
					ae.AllowedFileMatchPaths(path, &fileWhiteList, fromSources)
				} else if path.Action == "Audit" {
					ae.AuditedFileMatchPaths(path, &fileAuditList, fromSources)
				} else if path.Action == "Block" {
					ae.BlockedFileMatchPaths(path, &fileBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" {
					ae.AllowedFileMatchDirectories(dir, &fileWhiteList, fromSources)
				} else if dir.Action == "Audit" {
					ae.AuditedFileMatchDirectories(dir, &fileAuditList, fromSources)
				} else if dir.Action == "Block" {
					ae.BlockedFileMatchDirectories(dir, &fileBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.File.MatchPatterns {
				if pat.Action == "Allow" {
					ae.AllowedFileMatchPatterns(pat, &fileWhiteList)
				} else if pat.Action == "Audit" {
					ae.AuditedFileMatchPatterns(pat, &fileAuditList)
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

	// Resolve conflicts
	ae.ResolvedProcessWhiteListConflicts(&processWhiteList, fromSources, &fusionProcessWhiteList)

	// head

	profileHead := "  ## == PRE START == ##\n" + ae.GenerateProfileHead(processWhiteList, fileWhiteList, networkWhiteList, capabilityWhiteList) + "  ## == PRE END == ##\n\n"

	// body

	profileBody := ""

	// body - white list

	for _, line := range processWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(processWhiteList)

	for _, line := range fileWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(fileWhiteList)

	for _, line := range networkWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(networkWhiteList)

	for _, line := range capabilityWhiteList {
		profileBody = profileBody + line
	}

	count = count + len(capabilityWhiteList)

	// body - audit list

	for _, line := range processAuditList {
		profileBody = profileBody + line
	}

	count = count + len(processAuditList)

	for _, line := range fileAuditList {
		profileBody = profileBody + line
	}

	count = count + len(fileAuditList)

	// body - black list

	for _, line := range processBlackList {
		profileBody = profileBody + line
	}

	count = count + len(processBlackList)

	for _, line := range fileBlackList {
		profileBody = profileBody + line
	}

	count = count + len(fileBlackList)

	for _, line := range networkBlackList {
		profileBody = profileBody + line
	}

	count = count + len(networkBlackList)

	for _, line := range capabilityBlackList {
		profileBody = profileBody + line
	}

	count = count + len(capabilityBlackList)

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
				continue
			}

			if strings.Contains(line, "  capability") {
				capability = false
				continue
			}

			if strings.Contains(line, "  owner") {
				continue
			}

			if strings.Contains(line, "  deny") {
				continue
			}

			file = false
		}

		if file && len(processWhiteList) == 0 && len(fileWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "    file,\n"
		}

		if network && len(networkWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "    network,\n"
		}

		if capability && len(capabilityWhiteList) == 0 {
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
func (ae *AppArmorEnforcer) GenerateAppArmorProfile(appArmorProfile string, securityPolicies []tp.SecurityPolicy) (int, string, bool) {
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

	count, newProfileBody := ae.GenerateProfileBody(securityPolicies)

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
