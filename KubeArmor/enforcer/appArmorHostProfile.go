package enforcer

import (
	"bufio"
	"fmt"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

func allowedHostProcessMatchPaths(enableAuditd bool, path tp.ProcessPathType, fromSources map[string][]string) {
	if len(path.FromSource) > 0 {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func allowedHostProcessMatchDirectories(enableAuditd bool, dir tp.ProcessDirectoryType, fromSources map[string][]string) {
	if len(dir.FromSource) > 0 {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func allowedHostFileMatchPaths(enableAuditd bool, path tp.FilePathType, fromSources map[string][]string) {
	if len(path.FromSource) > 0 {
		for _, src := range path.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func allowedHostFileMatchDirectories(enableAuditd bool, dir tp.FileDirectoryType, fromSources map[string][]string) {
	if len(dir.FromSource) > 0 {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
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
}

func allowedHostNetworkMatchProtocols(proto tp.NetworkProtocolType, fromSources map[string][]string) {
	if len(proto.FromSource) > 0 {
		for _, src := range proto.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
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

func allowedHostCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, fromSources map[string][]string) {
	if len(cap.FromSource) > 0 {
		for _, src := range cap.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
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

func auditedHostProcessMatchPaths(enableAuditd bool, path tp.ProcessPathType, processAuditList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		} else { // !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit %s ix,\n", path.Path)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
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
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func auditedHostProcessMatchDirectories(enableAuditd bool, dir tp.ProcessDirectoryType, processAuditList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processAuditList, line) {
					*processAuditList = append(*processAuditList, line)
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
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func auditedHostProcessMatchPatterns(enableAuditd bool, pat tp.ProcessPatternType, processAuditList *[]string) {
	if pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		}
	} else { // !pat.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit %s* ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  %s* ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processAuditList, line) {
				*processAuditList = append(*processAuditList, line)
			}
		}
	}
}

func auditedHostFileMatchPaths(enableAuditd bool, path tp.FilePathType, fileAuditList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit %s r,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s r,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
			} else {
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileAuditList, line) {
					*fileAuditList = append(*fileAuditList, line)
				}
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
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func auditedHostFileMatchDirectories(enableAuditd bool, dir tp.FileDirectoryType, fileAuditList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				} else {
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileAuditList, line) {
						*fileAuditList = append(*fileAuditList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
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
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
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
}

func auditedHostFileMatchPatterns(enableAuditd bool, pat tp.FilePatternType, fileAuditList *[]string) {
	if pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		} else {
			line := fmt.Sprintf("  %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileAuditList, line) {
				*fileAuditList = append(*fileAuditList, line)
			}
		}
	}
}

//

func blockedHostProcessMatchPaths(enableAuditd bool, path tp.ProcessPathType, processBlackList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		} else { // !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s x,\n", path.Path)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
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
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s x,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func blockedHostProcessMatchDirectories(enableAuditd bool, dir tp.ProcessDirectoryType, processBlackList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		} else if dir.Recursive && !dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		} else if !dir.Recursive && dir.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			}
		} else { // !dir.Recursive && !dir.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
				if !kl.ContainsElement(*processBlackList, line) {
					*processBlackList = append(*processBlackList, line)
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
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if dir.Recursive && !dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !dir.Recursive && dir.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !dir.Recursive && !dir.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func blockedHostProcessMatchPatterns(enableAuditd bool, pat tp.ProcessPatternType, processBlackList *[]string) {
	if pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		}
	} else { // !path.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit deny %s x,\n", pat.Pattern)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  deny %s x,\n", pat.Pattern)
			if !kl.ContainsElement(*processBlackList, line) {
				*processBlackList = append(*processBlackList, line)
			}
		}
	}
}

func blockedHostFileMatchPaths(enableAuditd bool, path tp.FilePathType, fileBlackList *[]string, fromSources map[string][]string) {
	if len(path.FromSource) == 0 {
		if path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		} else if path.ReadOnly && !path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s w,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s w,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		} else if !path.ReadOnly && path.OwnerOnly {
			if enableAuditd {
				line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			}
		} else { // !path.ReadOnly && !path.OwnerOnly
			if enableAuditd {
				line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
			} else {
				line := fmt.Sprintf("  deny %s rw,\n", path.Path)
				if !kl.ContainsElement(*fileBlackList, line) {
					*fileBlackList = append(*fileBlackList, line)
				}
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
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if path.ReadOnly && !path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s w,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s w,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else if !path.ReadOnly && path.OwnerOnly {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			} else { // !path.ReadOnly && !path.OwnerOnly
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else {
					line := fmt.Sprintf("  deny %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func blockedHostFileMatchDirectories(enableAuditd bool, dir tp.FileDirectoryType, fileBlackList *[]string, fromSources map[string][]string) {
	if len(dir.FromSource) == 0 {
		if dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			}
		} else if dir.ReadOnly && !dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s{*,**} w,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s* w,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			}
		} else if !dir.ReadOnly && dir.OwnerOnly {
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			}
		} else { // !dir.ReadOnly && !dir.OwnerOnly
			if dir.Recursive {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				} else {
					line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
					if !kl.ContainsElement(*fileBlackList, line) {
						*fileBlackList = append(*fileBlackList, line)
					}
				}
			} else {
				if enableAuditd {
					line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
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
		}
	} else {
		for _, src := range dir.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit deny %s{*,**} w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit deny %s* w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					if enableAuditd {
						line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else {
					if enableAuditd {
						line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
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
}

func blockedHostFileMatchPatterns(enableAuditd bool, pat tp.FilePatternType, fileBlackList *[]string) {
	if pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		}
	} else if pat.ReadOnly && !pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit deny %s w,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  deny %s w,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		}
	} else if !pat.ReadOnly && pat.OwnerOnly {
		if enableAuditd {
			line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		}
	} else { // !pat.ReadOnly && !pat.OwnerOnly
		if enableAuditd {
			line := fmt.Sprintf("  audit deny %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		} else {
			line := fmt.Sprintf("  deny %s rw,\n", pat.Pattern)
			if !kl.ContainsElement(*fileBlackList, line) {
				*fileBlackList = append(*fileBlackList, line)
			}
		}
	}
}

func blockedHostNetworkMatchProtocols(proto tp.NetworkProtocolType, fromSources map[string][]string) {
	if len(proto.FromSource) > 0 {
		for _, src := range proto.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
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

func blockedHostCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, fromSources map[string][]string) {
	if len(cap.FromSource) > 0 {
		for _, src := range cap.FromSource {
			source := ""

			if len(src.Path) > 0 {
				source = src.Path
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(src.Directory) > 0 {
				if src.Recursive {
					source = fmt.Sprintf("%s{*,**}", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", src.Directory)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
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
func GenerateHostProfileHead() string {
	profileHead := "## == Managed by KubeArmor == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile kubearmor.host /** flags=(attach_disconnected,mediate_deleted) {\n" +
		"  #include <abstractions/base>\n" +
		"\n" +
		"  file,\n" +
		"  mount,\n" +
		"  umount,\n" +
		"  ptrace,\n" +
		"  network,\n" +
		"  capability,\n" +
		"\n" +
		"  /usr/bin/runc Ux,\n" + // docker
		"  /usr/bin/docker-runc Ux, \n" + // docker
		"  /usr/sbin/runc Ux,\n" + // containerd
		"  /snap/microk8s/2262/bin/runc Ux,\n" + // microk8s
		"  /snap/microk8s/2264/bin/runc Ux,\n" + // microk8s
		"\n" +
		"  ## == POLICY START == ##\n"

	return profileHead
}

// GenerateHostProfileFoot Function
func GenerateHostProfileFoot() string {
	profileFoot := "  ## == POLICY END == ##\n" +
		"}\n"

	return profileFoot
}

// == //

// GenerateHostProfileBody Function
func GenerateHostProfileBody(enableAuditd bool, securityPolicies []tp.HostSecurityPolicy) (int, string) {
	// preparation

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
				if path.Action == "Allow" || path.Action == "AllowWithAudit" {
					allowedHostProcessMatchPaths(enableAuditd, path, fromSources)
				} else if path.Action == "Audit" {
					auditedHostProcessMatchPaths(enableAuditd, path, &processAuditList, fromSources)
				} else if path.Action == "Block" || path.Action == "BlockWithAudit" {
					blockedHostProcessMatchPaths(enableAuditd, path, &processBlackList, fromSources)
				}
			}
		} else if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" || dir.Action == "AllowWithAudit" {
					allowedHostProcessMatchDirectories(enableAuditd, dir, fromSources)
				} else if dir.Action == "Audit" {
					auditedHostProcessMatchDirectories(enableAuditd, dir, &processAuditList, fromSources)
				} else if dir.Action == "Block" || dir.Action == "BlockWithAudit" {
					blockedHostProcessMatchDirectories(enableAuditd, dir, &processBlackList, fromSources)
				}
			}
		} else if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.Process.MatchPatterns {
				if pat.Action == "Audit" {
					auditedHostProcessMatchPatterns(enableAuditd, pat, &processAuditList)
				} else if pat.Action == "Block" || pat.Action == "BlockWithAudit" {
					blockedHostProcessMatchPatterns(enableAuditd, pat, &processBlackList)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" || path.Action == "AllowWithAudit" {
					allowedHostFileMatchPaths(enableAuditd, path, fromSources)
				} else if path.Action == "Audit" {
					auditedHostFileMatchPaths(enableAuditd, path, &fileAuditList, fromSources)
				} else if path.Action == "Block" || path.Action == "BlockWithAudit" {
					blockedHostFileMatchPaths(enableAuditd, path, &fileBlackList, fromSources)
				}
			}
		} else if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" || dir.Action == "AllowWithAudit" {
					allowedHostFileMatchDirectories(enableAuditd, dir, fromSources)
				} else if dir.Action == "Audit" {
					auditedHostFileMatchDirectories(enableAuditd, dir, &fileAuditList, fromSources)
				} else if dir.Action == "Block" || dir.Action == "BlockWithAudit" {
					blockedHostFileMatchDirectories(enableAuditd, dir, &fileBlackList, fromSources)
				}
			}
		} else if len(secPolicy.Spec.File.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.File.MatchPatterns {
				if pat.Action == "Audit" {
					auditedHostFileMatchPatterns(enableAuditd, pat, &fileAuditList)
				} else if pat.Action == "Block" || pat.Action == "BlockWithAudit" {
					blockedHostFileMatchPatterns(enableAuditd, pat, &fileBlackList)
				}
			}
		}

		if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
			for _, proto := range secPolicy.Spec.Network.MatchProtocols {
				if proto.Action == "Allow" || proto.Action == "AllowWithAudit" {
					allowedHostNetworkMatchProtocols(proto, fromSources)
				} else if proto.Action == "Block" || proto.Action == "BlockWithAudit" {
					blockedHostNetworkMatchProtocols(proto, fromSources)
				}
			}
		}

		if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
			for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
				if cap.Action == "Allow" || cap.Action == "AllowWithAudit" {
					allowedHostCapabilitiesMatchCapabilities(cap, fromSources)
				} else if cap.Action == "Block" || cap.Action == "BlockWithAudit" {
					blockedHostCapabilitiesMatchCapabilities(cap, fromSources)
				}
			}
		}
	}

	// body

	profileBody := ""

	// body - from source

	bodyFromSource := ""

	for source, lines := range fromSources {
		bodyFromSource = bodyFromSource + fmt.Sprintf("  %s cx,\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("  profile %s {\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("    %s r,\n", source)

		bodyFromSource = bodyFromSource + "    #include <abstractions/base>\n"
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

			if strings.Contains(line, "  audit owner") {
				continue
			}

			if strings.Contains(line, "  audit deny") {
				continue
			}

			file = false
		}

		if file {
			bodyFromSource = bodyFromSource + "    file,\n"
		}

		bodyFromSource = bodyFromSource + "    mount,\n"
		bodyFromSource = bodyFromSource + "    umount,\n"
		bodyFromSource = bodyFromSource + "    ptrace,\n"

		if network {
			bodyFromSource = bodyFromSource + "    network,\n"
		}

		if capability {
			bodyFromSource = bodyFromSource + "    capability,\n"
		}

		bodyFromSource = bodyFromSource + "    /usr/bin/runc Ux,\n"
		bodyFromSource = bodyFromSource + "\n"

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY START (%s) == ##\n\n", source)

		//

		for _, line := range lines {
			bodyFromSource = bodyFromSource + "  " + line
		}

		//

		bodyFromSource = bodyFromSource + fmt.Sprintf("    ## == POLICY END (%s) == ##\n\n", source)
		bodyFromSource = bodyFromSource + "  }\n"
	}

	for _, source := range fromSources {
		count = count + len(source)
	}

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

	// body - native apparmor

	if len(nativeAppArmorRules) > 0 {
		profileBody = profileBody + "\n  ## == NATIVE POLICY START == ##\n"
		for _, nativeRule := range nativeAppArmorRules {
			profileBody = profileBody + nativeRule
		}
		profileBody = profileBody + "  ## == NATIVE POLICY END == ##\n"
	}

	count = count + len(nativeAppArmorRules)

	// finalization

	profile := bodyFromSource + profileBody

	return count, profile
}

// GenerateAppArmorHostProfile Function
func (ae *AppArmorEnforcer) GenerateAppArmorHostProfile(secPolicies []tp.HostSecurityPolicy) (int, string, bool) {

	// generate a profile body

	count, profileBody := GenerateHostProfileBody(ae.EnableAuditd, secPolicies)

	// generate a new profile

	newProfile := ""

	// head

	newProfile = newProfile + GenerateHostProfileHead()

	// body

	newProfile = newProfile + profileBody

	// foot

	newProfile = newProfile + GenerateHostProfileFoot()

	if ae.HostProfile != newProfile {
		ae.HostProfile = newProfile
		return count, newProfile, true
	}

	return 0, "", false
}
