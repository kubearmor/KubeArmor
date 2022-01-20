// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"bufio"
	"fmt"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

// AllowedHostProcessMatchPaths Function
func (ae *AppArmorEnforcer) AllowedHostProcessMatchPaths(path tp.ProcessPathType, fromSources map[string][]string) {
	if len(path.FromSource) > 0 {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}

			}
		}
	}
}

// AllowedHostProcessMatchDirectories Function
func (ae *AppArmorEnforcer) AllowedHostProcessMatchDirectories(dir tp.ProcessDirectoryType, fromSources map[string][]string) {
	if len(dir.FromSource) > 0 {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			}
		}
	}
}

// AllowedHostFileMatchPaths Function
func (ae *AppArmorEnforcer) AllowedHostFileMatchPaths(path tp.FilePathType, fromSources map[string][]string) {
	if len(path.FromSource) > 0 {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  %s r,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			}
		}
	}
}

// AllowedHostFileMatchDirectories Function
func (ae *AppArmorEnforcer) AllowedHostFileMatchDirectories(dir tp.FileDirectoryType, fromSources map[string][]string) {
	if len(dir.FromSource) > 0 {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

// AllowedHostNetworkMatchProtocols Function
func (ae *AppArmorEnforcer) AllowedHostNetworkMatchProtocols(proto tp.NetworkProtocolType, fromSources map[string][]string) {
	if len(proto.FromSource) > 0 {
		for _, src := range proto.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  network %s,\n", proto.Protocol)
			if !kl.ContainsElement(fromSources[source], line) {
				fromSources[source] = append(fromSources[source], line)
			}
		}
	}
}

// AllowedHostCapabilitiesMatchCapabilities Function
func (ae *AppArmorEnforcer) AllowedHostCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, fromSources map[string][]string) {
	if len(cap.FromSource) > 0 {
		for _, src := range cap.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  capability %s,\n", cap.Capability)
			if !kl.ContainsElement(fromSources[source], line) {
				fromSources[source] = append(fromSources[source], line)
			}
		}
	}
}

//

// AuditedHostProcessMatchPaths Function
func (ae *AppArmorEnforcer) AuditedHostProcessMatchPaths(path tp.ProcessPathType, processAuditList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			line := fmt.Sprintf("  owner %s ix,\n", path.Path)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		} else { // !path.OwnerOnly
			line := fmt.Sprintf("  %s ix,\n", path.Path)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			}
		}
	}
}

// AuditedHostProcessMatchDirectories Function
func (ae *AppArmorEnforcer) AuditedHostProcessMatchDirectories(dir tp.ProcessDirectoryType, processAuditList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			}
		}
	}
}

// AuditedHostProcessMatchPatterns Function
func (ae *AppArmorEnforcer) AuditedHostProcessMatchPatterns(pat tp.ProcessPatternType, processAuditList *[]string) {
	if pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
		if !kl.ContainsElement(*processAuditList, line) {
			*processAuditList = append(*processAuditList, line)
		}
	} else { // !pat.OwnerOnly
		line := fmt.Sprintf("  %s* ix,\n", pat.Pattern)
		if !kl.ContainsElement(*processAuditList, line) {
			*processAuditList = append(*processAuditList, line)
		}
	}
}

// AuditedHostFileMatchPaths Function
func (ae *AppArmorEnforcer) AuditedHostFileMatchPaths(path tp.FilePathType, fileAuditList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  owner %s r,\n", path.Path)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			line := fmt.Sprintf("  %s r,\n", path.Path)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  owner %s rw,\n", path.Path)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			line := fmt.Sprintf("  %s rw,\n", path.Path)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  %s r,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			}
		}
	}
}

// AuditedHostFileMatchDirectories Function
func (ae *AppArmorEnforcer) AuditedHostFileMatchDirectories(dir tp.FileDirectoryType, fileAuditList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s* r,\n", dir.Directory)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

// AuditedHostFileMatchPatterns Function
func (ae *AppArmorEnforcer) AuditedHostFileMatchPatterns(pat tp.FilePatternType, fileAuditList *[]string) {
	if pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
		if !kl.ContainsElement(*fileAuditList, line) {
			*fileAuditList = append(*fileAuditList, line)
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		line := fmt.Sprintf("  %s r,\n", pat.Pattern)
		if !kl.ContainsElement(*fileAuditList, line) {
			*fileAuditList = append(*fileAuditList, line)
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
		if !kl.ContainsElement(*fileAuditList, line) {
			*fileAuditList = append(*fileAuditList, line)
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		line := fmt.Sprintf("  %s rw,\n", pat.Pattern)
		if !kl.ContainsElement(*fileAuditList, line) {
			*fileAuditList = append(*fileAuditList, line)
		}
	}
}

//

// BlockedHostProcessMatchPaths Function
func (ae *AppArmorEnforcer) BlockedHostProcessMatchPaths(path tp.ProcessPathType, processBlackList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			line := fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", path.Path, path.Path)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		} else { // !path.OwnerOnly
			line := fmt.Sprintf("  deny %s x,\n", path.Path)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", path.Path, path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  deny %s x,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			}
		}
	}
}

// BlockedHostProcessMatchDirectories Function
func (ae *AppArmorEnforcer) BlockedHostProcessMatchDirectories(dir tp.ProcessDirectoryType, processBlackList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s{*,**} ix,\n  deny other %s{*,**} x,\n", dir.Directory, dir.Directory)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			line := fmt.Sprintf("  owner %s* ix,\n  deny other %s* x,\n", dir.Directory, dir.Directory)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n  deny other %s{*,**} x,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s* ix,\n  deny other %s* x,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			}
		}
	}
}

// BlockedHostProcessMatchPatterns Function
func (ae *AppArmorEnforcer) BlockedHostProcessMatchPatterns(pat tp.ProcessPatternType, processBlackList *[]string) {
	if pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s ix,\n  deny other %s x,\n", pat.Pattern, pat.Pattern)
		if !kl.ContainsElement(*processBlackList, line) {
			*processBlackList = append(*processBlackList, line)
		}
	} else { // !path.OwnerOnly
		line := fmt.Sprintf("  deny %s x,\n", pat.Pattern)
		if !kl.ContainsElement(*processBlackList, line) {
			*processBlackList = append(*processBlackList, line)
		}
	}
}

// BlockedHostFileMatchPaths Function
func (ae *AppArmorEnforcer) BlockedHostFileMatchPaths(path tp.FilePathType, fileBlackList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  deny owner %s w,\n  deny other %s rw,\n", path.Path, path.Path)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			line := fmt.Sprintf("  deny %s w,\n", path.Path)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			line := fmt.Sprintf("  owner %s rw,\n  deny other %s rw,\n", path.Path, path.Path)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			line := fmt.Sprintf("  deny %s rw,\n", path.Path)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		}
	} else {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  deny owner %s w,\n  deny other %s rw,\n", path.Path, path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  deny %s w,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s rw,\n  deny other %s rw,\n", path.Path, path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  deny %s rw,\n", path.Path)
				if !kl.ContainsElement(fromSources[source], line) {
					fromSources[source] = append(fromSources[source], line)
				}
			}
		}
	}
}

// BlockedHostFileMatchDirectories Function
func (ae *AppArmorEnforcer) BlockedHostFileMatchDirectories(dir tp.FileDirectoryType, fileBlackList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  deny owner %s{*,**} w,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny owner %s* w,\n  deny other %s* rw,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				line := fmt.Sprintf("  owner %s{*,**} rw,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* rw,\n  deny other %s* w,\n", dir.Directory, dir.Directory)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s* rw,\n", dir.Directory)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  deny owner %s{*,**} w,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny owner %s* w,\n  deny other %s* rw,\n", dir.Directory, dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n  deny other %s{*,**} rw,\n", dir.Directory, dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n  deny other %s* w,\n", dir.Directory, dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

// BlockedHostFileMatchPatterns Function
func (ae *AppArmorEnforcer) BlockedHostFileMatchPatterns(pat tp.FilePatternType, fileBlackList *[]string) {
	if pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  deny owner %s w,\n  deny other %s rw,\n", pat.Pattern, pat.Pattern)
		if !kl.ContainsElement(*fileBlackList, line) {
			*fileBlackList = append(*fileBlackList, line)
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		line := fmt.Sprintf("  deny %s w,\n", pat.Pattern)
		if !kl.ContainsElement(*fileBlackList, line) {
			*fileBlackList = append(*fileBlackList, line)
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		line := fmt.Sprintf("  owner %s rw,\n  deny other %s rw,\n", pat.Pattern, pat.Pattern)
		if !kl.ContainsElement(*fileBlackList, line) {
			*fileBlackList = append(*fileBlackList, line)
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		line := fmt.Sprintf("  deny %s rw,\n", pat.Pattern)
		if !kl.ContainsElement(*fileBlackList, line) {
			*fileBlackList = append(*fileBlackList, line)
		}
	}
}

// BlockedHostNetworkMatchProtocols Function
func (ae *AppArmorEnforcer) BlockedHostNetworkMatchProtocols(proto tp.NetworkProtocolType, fromSources map[string][]string) {
	if len(proto.FromSource) > 0 {
		for _, src := range proto.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  deny network %s,\n", proto.Protocol)
			if !kl.ContainsElement(fromSources[source], line) {
				fromSources[source] = append(fromSources[source], line)
			}
		}
	}
}

// BlockedHostCapabilitiesMatchCapabilities Function
func (ae *AppArmorEnforcer) BlockedHostCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, fromSources map[string][]string) {
	if len(cap.FromSource) > 0 {
		for _, src := range cap.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else {
				continue
			}

			line := fmt.Sprintf("  deny capability %s,\n", cap.Capability)
			if !kl.ContainsElement(fromSources[source], line) {
				fromSources[source] = append(fromSources[source], line)
			}
		}
	}
}

// == //

// GenerateHostProfileHead Function
func (ae *AppArmorEnforcer) GenerateHostProfileHead() string {
	profileHead := "## == Managed by KubeArmor == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile kubearmor.host /{usr/,}bin/*sh flags=(attach_disconnected,mediate_deleted) {\n" +
		"  ## == PRE START == ##\n" +
		"  #include <abstractions/base>\n" +
		"  mount,\n" +
		"  umount,\n" +
		"  signal,\n" +
		"  unix,\n" +
		"\n" +
		"  file,\n" +
		"  network,\n" +
		"  capability,\n" +
		"  ## == PRE END == ##\n" +
		"\n"

	return profileHead
}

// GenerateHostProfileFoot Function
func (ae *AppArmorEnforcer) GenerateHostProfileFoot() string {
	profileFoot := "}\n"

	return profileFoot
}

// == //

// GenerateHostProfileBody Function
func (ae *AppArmorEnforcer) GenerateHostProfileBody(securityPolicies []tp.HostSecurityPolicy) (int, string) {
	count := 0

	processAuditList := []string{}
	processBlackList := []string{}

	fileAuditList := []string{}
	fileBlackList := []string{}

	fromSources := map[string][]string{}

	nativeAppArmorRules := []string{}

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
					ae.AllowedHostProcessMatchPaths(path, fromSources)
				} else if path.Action == "Audit" {
					ae.AuditedHostProcessMatchPaths(path, &processAuditList, fromSources)
				} else if path.Action == "Block" {
					ae.BlockedHostProcessMatchPaths(path, &processBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" {
					ae.AllowedHostProcessMatchDirectories(dir, fromSources)
				} else if dir.Action == "Audit" {
					ae.AuditedHostProcessMatchDirectories(dir, &processAuditList, fromSources)
				} else if dir.Action == "Block" {
					ae.BlockedHostProcessMatchDirectories(dir, &processBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.Process.MatchPatterns {
				if pat.Action == "Audit" {
					ae.AuditedHostProcessMatchPatterns(pat, &processAuditList)
				} else if pat.Action == "Block" {
					ae.BlockedHostProcessMatchPatterns(pat, &processBlackList)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" {
					ae.AllowedHostFileMatchPaths(path, fromSources)
				} else if path.Action == "Audit" {
					ae.AuditedHostFileMatchPaths(path, &fileAuditList, fromSources)
				} else if path.Action == "Block" {
					ae.BlockedHostFileMatchPaths(path, &fileBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" {
					ae.AllowedHostFileMatchDirectories(dir, fromSources)
				} else if dir.Action == "Audit" {
					ae.AuditedHostFileMatchDirectories(dir, &fileAuditList, fromSources)
				} else if dir.Action == "Block" {
					ae.BlockedHostFileMatchDirectories(dir, &fileBlackList, fromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.File.MatchPatterns {
				if pat.Action == "Audit" {
					ae.AuditedHostFileMatchPatterns(pat, &fileAuditList)
				} else if pat.Action == "Block" {
					ae.BlockedHostFileMatchPatterns(pat, &fileBlackList)
				}
			}
		}

		if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
			for _, proto := range secPolicy.Spec.Network.MatchProtocols {
				if proto.Action == "Allow" {
					ae.AllowedHostNetworkMatchProtocols(proto, fromSources)
				} else if proto.Action == "Block" {
					ae.BlockedHostNetworkMatchProtocols(proto, fromSources)
				}
			}
		}

		if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
			for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
				if cap.Action == "Allow" {
					ae.AllowedHostCapabilitiesMatchCapabilities(cap, fromSources)
				} else if cap.Action == "Block" {
					ae.BlockedHostCapabilitiesMatchCapabilities(cap, fromSources)
				}
			}
		}
	}

	// body

	profileBody := ""

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

	// body - from source

	bodyFromSource := ""

	for source, lines := range fromSources {
		bodyFromSource = bodyFromSource + fmt.Sprintf("  %s cx,\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("  profile %s {\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("    %s rix,\n", source)

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == PRE START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + "    #include <abstractions/base>\n"
		bodyFromSource = bodyFromSource + "    mount,\n"
		bodyFromSource = bodyFromSource + "    umount,\n"
		bodyFromSource = bodyFromSource + "    signal,\n"
		bodyFromSource = bodyFromSource + "    unix,\n"
		bodyFromSource = bodyFromSource + "\n"

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

		if file {
			bodyFromSource = bodyFromSource + "    file,\n"
		}

		if network {
			bodyFromSource = bodyFromSource + "    network,\n"
		}

		if capability {
			bodyFromSource = bodyFromSource + "    capability,\n"
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == PRE END (%s) == ##\n\n", source)

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + strings.Replace(profileBody, "  ", "    ", -1)

		for _, line := range lines {
			bodyFromSource = bodyFromSource + "  " + line
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY END (%s) == ##\n", source)
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

	return count, profileBody
}

// GenerateAppArmorHostProfile Function
func (ae *AppArmorEnforcer) GenerateAppArmorHostProfile(secPolicies []tp.HostSecurityPolicy) (int, string, bool) {

	// generate a profile body

	count, profileBody := ae.GenerateHostProfileBody(secPolicies)

	// generate a new profile

	newProfile := ae.GenerateHostProfileHead() + profileBody + ae.GenerateHostProfileFoot()

	// check the new profile with the old profile

	if ae.HostProfile != newProfile {
		ae.HostProfile = newProfile
		return count, newProfile, true
	}

	return 0, "", false
}
