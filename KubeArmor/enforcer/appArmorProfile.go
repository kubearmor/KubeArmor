package enforcer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

func headFromSource(src tp.MatchSourceType, lines []string) []string {
	if src.Path != "" {
		line := fmt.Sprintf("  profile %s {\n", src.Path)
		lines = append(lines, line)
	} else if src.Directory != "" && !src.Recursive {
		line := fmt.Sprintf("  profile %s* {\n", src.Directory)
		lines = append(lines, line)
	} else if src.Directory != "" && src.Recursive {
		line := fmt.Sprintf("  profile %s{*,**} {\n", src.Directory)
		lines = append(lines, line)
	}

	return lines
}

func footFromSource(src tp.MatchSourceType, lines []string) []string {
	if src.Path != "" || src.Directory != "" {
		line := fmt.Sprintf("  }\n")
		lines = append(lines, line)
	}

	return lines
}

func allowedProcesses(secPolicy tp.SecurityPolicy, allowLines []string, allowCount int) ([]string, int) {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if len(path.FromSource) > 0 {
				for _, src := range path.FromSource {
					allowLines = headFromSource(src, allowLines)

					if path.OwnerOnly {
						line := fmt.Sprintf("    owner %s ix,\n", path.Path)
						allowLines = append(allowLines, line)
						allowCount++
					} else { // !path.OwnerOnly
						line := fmt.Sprintf("    %s ix,\n", path.Path)
						allowLines = append(allowLines, line)
						allowCount++
					}

					allowLines = footFromSource(src, allowLines)
				}
			} else { // no FromSource
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
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if len(dir.FromSource) > 0 {
				for _, src := range dir.FromSource {
					allowLines = headFromSource(src, allowLines)

					if dir.Recursive && dir.OwnerOnly {
						line := fmt.Sprintf("    owner %s{*,**} ix,\n", dir.Directory)
						allowLines = append(allowLines, line)
						allowCount++
					} else if dir.Recursive && !dir.OwnerOnly {
						line := fmt.Sprintf("    %s{*,**} ix,\n", dir.Directory)
						allowLines = append(allowLines, line)
						allowCount++
					} else if !dir.Recursive && dir.OwnerOnly {
						line := fmt.Sprintf("    owner %s* ix,\n", dir.Directory)
						allowLines = append(allowLines, line)
						allowCount++
					} else { // !dir.Recursive && !dir.OwnerOnly
						line := fmt.Sprintf("    %s* ix,\n", dir.Directory)
						allowLines = append(allowLines, line)
						allowCount++
					}

					allowLines = footFromSource(src, allowLines)
				}
			} else { // no FromSource
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
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			if len(pat.FromSource) > 0 {
				for _, src := range pat.FromSource {
					allowLines = headFromSource(src, allowLines)

					if pat.OwnerOnly {
						line := fmt.Sprintf("    owner %s ix,\n", pat.Pattern)
						allowLines = append(allowLines, line)
						allowCount++
					} else { // !pat.OwnerOnly
						line := fmt.Sprintf("    %s ix,\n", pat.Pattern)
						allowLines = append(allowLines, line)
						allowCount++
					}

					allowLines = footFromSource(src, allowLines)
				}
			} else { // no FromSource
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
	}

	return allowLines, allowCount
}

func allowedFiles(secPolicy tp.SecurityPolicy, allowLines []string, allowCount int) ([]string, int) {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if len(path.FromSource) > 0 {
				for _, src := range path.FromSource {
					allowLines = headFromSource(src, allowLines)

					if path.ReadOnly && path.OwnerOnly {
						line := fmt.Sprintf("    owner %s r,\n", path.Path)
						allowLines = append(allowLines, line)
						allowCount++
					} else if path.ReadOnly && !path.OwnerOnly {
						line := fmt.Sprintf("    %s r,\n", path.Path)
						allowLines = append(allowLines, line)
						allowCount++
					} else if !path.ReadOnly && path.OwnerOnly {
						line := fmt.Sprintf("    owner %s rw,\n", path.Path)
						allowLines = append(allowLines, line)
						allowCount++
					} else { // !path.ReadOnly && !path.OwnerOnly
						line := fmt.Sprintf("    %s rw,\n", path.Path)
						allowLines = append(allowLines, line)
						allowCount++
					}

					allowLines = footFromSource(src, allowLines)
				}
			} else { // no FromSource
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
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if len(dir.FromSource) > 0 {
				for _, src := range dir.FromSource {
					allowLines = headFromSource(src, allowLines)

					if dir.ReadOnly && dir.OwnerOnly {
						if dir.Recursive {
							line := fmt.Sprintf("    owner %s{*,**} r,\n", dir.Directory)
							allowLines = append(allowLines, line)
							allowCount++
						} else {
							line := fmt.Sprintf("    owner %s* r,\n", dir.Directory)
							allowLines = append(allowLines, line)
							allowCount++
						}
					} else if dir.ReadOnly && !dir.OwnerOnly {
						if dir.Recursive {
							line := fmt.Sprintf("    %s{*,**} r,\n", dir.Directory)
							allowLines = append(allowLines, line)
							allowCount++
						} else {
							line := fmt.Sprintf("    %s* r,\n", dir.Directory)
							allowLines = append(allowLines, line)
							allowCount++
						}
					} else if !dir.ReadOnly && dir.OwnerOnly {
						if dir.Recursive {
							line := fmt.Sprintf("    owner %s{*,**} rw,\n", dir.Directory)
							allowLines = append(allowLines, line)
							allowCount++
						} else {
							line := fmt.Sprintf("    owner %s* rw,\n", dir.Directory)
							allowLines = append(allowLines, line)
							allowCount++
						}
					} else { // !dir.ReadOnly && !dir.OwnerOnly
						if dir.Recursive {
							line := fmt.Sprintf("    %s{*,**} rw,\n", dir.Directory)
							allowLines = append(allowLines, line)
							allowCount++
						} else {
							line := fmt.Sprintf("    %s* rw,\n", dir.Directory)
							allowLines = append(allowLines, line)
							allowCount++
						}
					}

					allowLines = footFromSource(src, allowLines)
				}
			} else { // no FromSource
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
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if len(pat.FromSource) > 0 {
				for _, src := range pat.FromSource {
					allowLines = headFromSource(src, allowLines)

					if pat.ReadOnly && pat.OwnerOnly {
						line := fmt.Sprintf("    owner %s r,\n", pat.Pattern)
						allowLines = append(allowLines, line)
						allowCount++
					} else if pat.ReadOnly && !pat.OwnerOnly {
						line := fmt.Sprintf("    %s r,\n", pat.Pattern)
						allowLines = append(allowLines, line)
						allowCount++
					} else if !pat.ReadOnly && pat.OwnerOnly {
						line := fmt.Sprintf("    owner %s rw,\n", pat.Pattern)
						allowLines = append(allowLines, line)
						allowCount++
					} else { // !pat.ReadOnly && !pat.OwnerOnly
						line := fmt.Sprintf("    %s rw,\n", pat.Pattern)
						allowLines = append(allowLines, line)
						allowCount++
					}

					allowLines = footFromSource(src, allowLines)
				}
			} else { // no FromSource
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
	}

	return allowLines, allowCount
}

func allowedNetworks(secPolicy tp.SecurityPolicy, allowLines []string, allowCount int, networkCount int) ([]string, int, int) {
	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if proto.IPv4 && proto.IPv6 {
				line := fmt.Sprintf("  network %s,\n", proto.Protocol)
				allowLines = append(allowLines, line)
			} else if proto.IPv4 && !proto.IPv6 {
				line := fmt.Sprintf("  network inet %s,\n", proto.Protocol)
				allowLines = append(allowLines, line)
			} else if !proto.IPv4 && proto.IPv6 {
				line := fmt.Sprintf("  network inet6 %s,\n", proto.Protocol)
				allowLines = append(allowLines, line)
			} else {
				line := fmt.Sprintf("  network %s,\n", proto.Protocol)
				allowLines = append(allowLines, line)
			}

			networkCount++
			allowCount++
		}
	}

	return allowLines, allowCount, networkCount
}

func allowedCapabilities(secPolicy tp.SecurityPolicy, allowLines []string, allowCount int, capabilitiesCount int) ([]string, int, int) {
	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			line := fmt.Sprintf("  capability %s\n", cap)
			allowLines = append(allowLines, line)
			capabilitiesCount++
			allowCount++
		}
	}

	return allowLines, allowCount, capabilitiesCount
}

func blockedProcesses(secPolicy tp.SecurityPolicy, denyLines []string, denyCount int) ([]string, int) {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if len(path.FromSource) > 0 {
				for _, src := range path.FromSource {
					denyLines = headFromSource(src, denyLines)

					line := fmt.Sprintf("    audit deny %s wklx,\n", path.Path)
					denyLines = append(denyLines, line)
					denyCount++

					denyLines = footFromSource(src, denyLines)
				}
			} else { // no FromSource
				line := fmt.Sprintf("  audit deny %s wklx,\n", path.Path)
				denyLines = append(denyLines, line)
				denyCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if len(dir.FromSource) > 0 {
				for _, src := range dir.FromSource {
					denyLines = headFromSource(src, denyLines)

					if dir.Recursive {
						line := fmt.Sprintf("    audit deny %s{*,**} wklx,\n", dir.Directory)
						denyLines = append(denyLines, line)
						denyCount++
					} else { // !dir.Recursive
						line := fmt.Sprintf("    audit deny %s* wklx,\n", dir.Directory)
						denyLines = append(denyLines, line)
						denyCount++
					}

					denyLines = footFromSource(src, denyLines)
				}
			} else { // no FromSource
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny %s{*,**} wklx,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				} else { // !dir.Recursive
					line := fmt.Sprintf("  audit deny %s* wklx,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				}
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			if len(pat.FromSource) > 0 {
				for _, src := range pat.FromSource {
					denyLines = headFromSource(src, denyLines)

					line := fmt.Sprintf("    audit deny %s wklx,\n", pat.Pattern)
					denyLines = append(denyLines, line)
					denyCount++

					denyLines = footFromSource(src, denyLines)
				}
			} else { // no FromSource
				line := fmt.Sprintf("  audit deny %s wklx,\n", pat.Pattern)
				denyLines = append(denyLines, line)
				denyCount++
			}
		}
	}

	return denyLines, denyCount
}

func blockedFiles(secPolicy tp.SecurityPolicy, denyLines []string, denyCount int) ([]string, int) {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if len(path.FromSource) > 0 {
				for _, src := range path.FromSource {
					denyLines = headFromSource(src, denyLines)

					if path.ReadOnly {
						line := fmt.Sprintf("    audit deny %s wkl,\n", path.Path)
						denyLines = append(denyLines, line)
						denyCount++
					} else { // !path.ReadOnly
						line := fmt.Sprintf("    audit deny %s rwkl,\n", path.Path)
						denyLines = append(denyLines, line)
						denyCount++
					}

					denyLines = footFromSource(src, denyLines)
				}
			} else { // no FromSource
				if path.ReadOnly {
					line := fmt.Sprintf("  audit deny %s wkl,\n", path.Path)
					denyLines = append(denyLines, line)
					denyCount++
				} else { // !path.ReadOnly
					line := fmt.Sprintf("  audit deny %s rwkl,\n", path.Path)
					denyLines = append(denyLines, line)
					denyCount++
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if len(dir.FromSource) > 0 {
				for _, src := range dir.FromSource {
					denyLines = headFromSource(src, denyLines)

					if dir.ReadOnly && dir.Recursive {
						line := fmt.Sprintf("    audit deny %s{*,**} wkl,\n", dir.Directory)
						denyLines = append(denyLines, line)
						denyCount++
					} else if dir.ReadOnly && !dir.Recursive {
						line := fmt.Sprintf("    audit deny %s* wkl,\n", dir.Directory)
						denyLines = append(denyLines, line)
						denyCount++
					} else if !dir.ReadOnly && dir.Recursive {
						line := fmt.Sprintf("    audit deny %s{*,**} rwkl,\n", dir.Directory)
						denyLines = append(denyLines, line)
						denyCount++
					} else { // !dir.ReadOnly && !dir.Recursive
						line := fmt.Sprintf("    audit deny %s* rwkl,\n", dir.Directory)
						denyLines = append(denyLines, line)
						denyCount++
					}

					denyLines = footFromSource(src, denyLines)
				}
			} else { // no FromSource
				if dir.ReadOnly && dir.Recursive {
					line := fmt.Sprintf("  audit deny %s{*,**} wkl,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				} else if dir.ReadOnly && !dir.Recursive {
					line := fmt.Sprintf("  audit deny %s* wkl,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				} else if !dir.ReadOnly && dir.Recursive {
					line := fmt.Sprintf("  audit deny %s{*,**} rwkl,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				} else { // !dir.ReadOnly && !dir.Recursive
					line := fmt.Sprintf("  audit deny %s* rwkl,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if len(pat.FromSource) > 0 {
				for _, src := range pat.FromSource {
					denyLines = headFromSource(src, denyLines)

					if pat.ReadOnly {
						line := fmt.Sprintf("    audit deny %s wkl,\n", pat.Pattern)
						denyLines = append(denyLines, line)
						denyCount++
					} else { // !pat.ReadOnly
						line := fmt.Sprintf("    audit deny %s rwkl,\n", pat.Pattern)
						denyLines = append(denyLines, line)
						denyCount++
					}

					denyLines = footFromSource(src, denyLines)
				}
			} else { // no FromSource
				if pat.ReadOnly {
					line := fmt.Sprintf("  audit deny %s wkl,\n", pat.Pattern)
					denyLines = append(denyLines, line)
					denyCount++
				} else { // !pat.ReadOnly
					line := fmt.Sprintf("  audit deny %s rwkl,\n", pat.Pattern)
					denyLines = append(denyLines, line)
					denyCount++
				}
			}
		}
	}

	return denyLines, denyCount
}

func blockedNetworks(secPolicy tp.SecurityPolicy, denyLines []string, denyCount int, networkCount int) ([]string, int, int) {
	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if proto.IPv4 && proto.IPv6 {
				line := fmt.Sprintf("  audit deny network %s,\n", proto.Protocol)
				denyLines = append(denyLines, line)
			} else if proto.IPv4 && !proto.IPv6 {
				line := fmt.Sprintf("  audit deny network inet %s,\n", proto.Protocol)
				denyLines = append(denyLines, line)
			} else if !proto.IPv4 && proto.IPv6 {
				line := fmt.Sprintf("  audit deny network inet6 %s,\n", proto.Protocol)
				denyLines = append(denyLines, line)
			} else {
				line := fmt.Sprintf("  audit deny network %s,\n", proto.Protocol)
				denyLines = append(denyLines, line)
			}

			networkCount++
			denyCount++
		}
	}

	return denyLines, denyCount, networkCount
}

func blockedCapabilities(secPolicy tp.SecurityPolicy, denyLines []string, denyCount int, capabilitiesCount int) ([]string, int, int) {
	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			line := fmt.Sprintf("  audit deny capability %s,\n", cap)
			denyLines = append(denyLines, line)
			capabilitiesCount++
			denyCount++
		}
	}

	return denyLines, denyCount, capabilitiesCount
}

func auditedProcesses(secPolicy tp.SecurityPolicy, auditLines []string, auditCount int) ([]string, int) {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if len(path.FromSource) > 0 {
				for _, src := range path.FromSource {
					auditLines = headFromSource(src, auditLines)

					line := fmt.Sprintf("    audit %s wklx,\n", path.Path)
					auditLines = append(auditLines, line)
					auditCount++

					auditLines = footFromSource(src, auditLines)
				}
			} else { // no FromSource
				line := fmt.Sprintf("  audit %s wklx,\n", path.Path)
				auditLines = append(auditLines, line)
				auditCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if len(dir.FromSource) > 0 {
				for _, src := range dir.FromSource {
					auditLines = headFromSource(src, auditLines)

					if dir.Recursive {
						line := fmt.Sprintf("    audit %s{*,**} wklx,\n", dir.Directory)
						auditLines = append(auditLines, line)
						auditCount++
					} else { // !dir.Recursive
						line := fmt.Sprintf("    audit %s* wklx,\n", dir.Directory)
						auditLines = append(auditLines, line)
						auditCount++
					}

					auditLines = footFromSource(src, auditLines)
				}
			} else { // no FromSource
				if dir.Recursive {
					line := fmt.Sprintf("  audit %s{*,**} wklx,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				} else { // !dir.Recursive
					line := fmt.Sprintf("  audit %s* wklx,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				}
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			if len(pat.FromSource) > 0 {
				for _, src := range pat.FromSource {
					auditLines = headFromSource(src, auditLines)

					line := fmt.Sprintf("    audit %s wklx,\n", pat.Pattern)
					auditLines = append(auditLines, line)
					auditCount++

					auditLines = footFromSource(src, auditLines)
				}
			} else { // no FromSource
				line := fmt.Sprintf("  audit %s wklx,\n", pat.Pattern)
				auditLines = append(auditLines, line)
				auditCount++
			}
		}
	}

	return auditLines, auditCount
}

func auditedFiles(secPolicy tp.SecurityPolicy, auditLines []string, auditCount int) ([]string, int) {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if len(path.FromSource) > 0 {
				for _, src := range path.FromSource {
					auditLines = headFromSource(src, auditLines)

					if path.ReadOnly {
						line := fmt.Sprintf("    audit %s wkl,\n", path.Path)
						auditLines = append(auditLines, line)
						auditCount++
					} else { // !path.ReadOnly
						line := fmt.Sprintf("    audit %s rwkl,\n", path.Path)
						auditLines = append(auditLines, line)
						auditCount++
					}

					auditLines = footFromSource(src, auditLines)
				}
			} else { // no FromSource
				if path.ReadOnly {
					line := fmt.Sprintf("  audit %s wkl,\n", path.Path)
					auditLines = append(auditLines, line)
					auditCount++
				} else { // !path.ReadOnly
					line := fmt.Sprintf("  audit %s rwkl,\n", path.Path)
					auditLines = append(auditLines, line)
					auditCount++
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if len(dir.FromSource) > 0 {
				for _, src := range dir.FromSource {
					auditLines = headFromSource(src, auditLines)

					if dir.ReadOnly && dir.Recursive {
						line := fmt.Sprintf("    audit %s{*,**} wkl,\n", dir.Directory)
						auditLines = append(auditLines, line)
						auditCount++
					} else if dir.ReadOnly && !dir.Recursive {
						line := fmt.Sprintf("    audit %s* wkl,\n", dir.Directory)
						auditLines = append(auditLines, line)
						auditCount++
					} else if !dir.ReadOnly && dir.Recursive {
						line := fmt.Sprintf("    audit %s{*,**} rwkl,\n", dir.Directory)
						auditLines = append(auditLines, line)
						auditCount++
					} else { // !dir.ReadOnly && !dir.Recursive
						line := fmt.Sprintf("    audit %s* rwkl,\n", dir.Directory)
						auditLines = append(auditLines, line)
						auditCount++
					}

					auditLines = footFromSource(src, auditLines)
				}
			} else { // no FromSource
				if dir.ReadOnly && dir.Recursive {
					line := fmt.Sprintf("  audit %s{*,**} wkl,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				} else if dir.ReadOnly && !dir.Recursive {
					line := fmt.Sprintf("  audit %s* wkl,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				} else if !dir.ReadOnly && dir.Recursive {
					line := fmt.Sprintf("  audit %s{*,**} rwkl,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				} else { // !dir.ReadOnly && !dir.Recursive
					line := fmt.Sprintf("  audit %s* rwkl,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if len(pat.FromSource) > 0 {
				for _, src := range pat.FromSource {
					auditLines = headFromSource(src, auditLines)

					if pat.ReadOnly {
						line := fmt.Sprintf("    audit %s wkl,\n", pat.Pattern)
						auditLines = append(auditLines, line)
						auditCount++
					} else { // !pat.ReadOnly
						line := fmt.Sprintf("    audit %s rwkl,\n", pat.Pattern)
						auditLines = append(auditLines, line)
						auditCount++
					}

					auditLines = footFromSource(src, auditLines)
				}
			} else { // no FromSource
				if pat.ReadOnly {
					line := fmt.Sprintf("  audit %s wkl,\n", pat.Pattern)
					auditLines = append(auditLines, line)
					auditCount++
				} else { // !pat.ReadOnly
					line := fmt.Sprintf("  audit %s rwkl,\n", pat.Pattern)
					auditLines = append(auditLines, line)
					auditCount++
				}
			}
		}
	}

	return auditLines, auditCount
}

func auditedNetworks(secPolicy tp.SecurityPolicy, auditLines []string, auditCount int, networkCount int) ([]string, int, int) {
	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if proto.IPv4 && proto.IPv6 {
				line := fmt.Sprintf("  audit network %s,\n", proto.Protocol)
				auditLines = append(auditLines, line)
			} else if proto.IPv4 && !proto.IPv6 {
				line := fmt.Sprintf("  audit network inet %s,\n", proto.Protocol)
				auditLines = append(auditLines, line)
			} else if !proto.IPv4 && proto.IPv6 {
				line := fmt.Sprintf("  audit network inet6 %s,\n", proto.Protocol)
				auditLines = append(auditLines, line)
			} else {
				line := fmt.Sprintf("  audit network %s,\n", proto.Protocol)
				auditLines = append(auditLines, line)
			}

			networkCount++
			auditCount++
		}
	}

	return auditLines, auditCount, networkCount
}

func auditedCapabilities(secPolicy tp.SecurityPolicy, auditLines []string, auditCount int, capabilitiesCount int) ([]string, int, int) {
	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			line := fmt.Sprintf("  audit capability %s,\n", cap)
			auditLines = append(auditLines, line)
			capabilitiesCount++
			auditCount++
		}
	}

	return auditLines, auditCount, capabilitiesCount
}

// UpdateAppArmorProfile Function
func (ae *AppArmorEnforcer) UpdateAppArmorProfile(conGroup tp.ContainerGroup, appArmorProfile string, securityPolicies []tp.SecurityPolicy) {
	// check apparmor profile

	if _, err := os.Stat("/etc/apparmor.d/" + appArmorProfile); os.IsNotExist(err) {
		return
	}

	// get the old profile

	oldProfile := ""

	oldContentsHead := []string{}
	oldContentsPreMid := []string{}
	oldConetntsMidPost := []string{}
	oldContentsFoot := []string{}

	file, _ := os.Open("/etc/apparmor.d/" + appArmorProfile)

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

	denyLines := []string{}
	denyCount := 0

	auditLines := []string{}
	auditCount := 0

	whiteList := false

	networkCount := 0
	capabilitiesCount := 0

	for _, secPolicy := range securityPolicies {
		if strings.ToLower(secPolicy.Spec.Action) == "allow" {
			whiteList = true

			// process
			allowLines, allowCount = allowedProcesses(secPolicy, allowLines, allowCount)

			// file
			allowLines, allowCount = allowedFiles(secPolicy, allowLines, allowCount)

			// network
			allowLines, allowCount, networkCount = allowedNetworks(secPolicy, allowLines, allowCount, networkCount)

			// capabilities
			allowLines, allowCount, capabilitiesCount = allowedCapabilities(secPolicy, allowLines, allowCount, capabilitiesCount)
		}
	}

	for _, secPolicy := range securityPolicies {
		if strings.ToLower(secPolicy.Spec.Action) == "block" {
			// process
			denyLines, denyCount = blockedProcesses(secPolicy, denyLines, denyCount)

			// file
			denyLines, denyCount = blockedFiles(secPolicy, denyLines, denyCount)

			// network
			denyLines, denyCount, networkCount = blockedNetworks(secPolicy, denyLines, denyCount, networkCount)

			// capabilities
			denyLines, denyCount, capabilitiesCount = blockedCapabilities(secPolicy, denyLines, denyCount, capabilitiesCount)
		}
	}

	for _, secPolicy := range securityPolicies {
		if strings.ToLower(secPolicy.Spec.Action) == "audit" {
			// process
			auditLines, auditCount = auditedProcesses(secPolicy, auditLines, auditCount)

			// file
			auditLines, auditCount = auditedFiles(secPolicy, auditLines, auditCount)

			// network
			auditLines, auditCount, networkCount = auditedNetworks(secPolicy, auditLines, auditCount, networkCount)

			// capabilities
			auditLines, auditCount, capabilitiesCount = auditedCapabilities(secPolicy, auditLines, auditCount, capabilitiesCount)
		}
	}

	newProfile := ""

	// head

	for _, head := range oldContentsHead {
		newProfile = newProfile + head
	}

	// pre

	newProfile = newProfile + "  ## == PRE START == ##\n"

	if !whiteList {
		newProfile = newProfile + "  file,\n"
	}

	if networkCount == 0 {
		newProfile = newProfile + "  network,\n"
	}

	if capabilitiesCount == 0 {
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

	newProfile = newProfile + "  ## == POLICY END == ##\n"

	// middle-post

	for _, midPost := range oldConetntsMidPost {
		newProfile = newProfile + midPost
	}

	// post

	newProfile = newProfile + "  ## == POST START == ##\n"

	if whiteList {
		newProfile = newProfile + "  /bin/bash ix,\n"
		newProfile = newProfile + "  /lib/x86_64-linux-gnu/{*,**} ix,\n"
	}

	newProfile = newProfile + "  ## == POST END == ##\n"

	// foot

	for _, foot := range oldContentsFoot {
		newProfile = newProfile + foot
	}

	// apply the new profile

	if newProfile != oldProfile {
		newfile, _ := os.Create("/etc/apparmor.d/" + appArmorProfile)
		defer newfile.Close()

		if _, err := newfile.WriteString(newProfile); err != nil {
			kg.Err(err.Error())
			return
		}

		if err := newfile.Sync(); err != nil {
			kg.Err(err.Error())
			return
		}

		if err := exec.Command("/sbin/apparmor_parser", "-r", "-W", "/etc/apparmor.d/"+appArmorProfile).Run(); err == nil {
			kg.Printf("Updated %d security policies to %s/%s/%s", allowCount+denyCount, conGroup.NamespaceName, conGroup.ContainerGroupName, appArmorProfile)
		} else {
			kg.Printf("Failed to update %d security policies to %s/%s/%s", allowCount+denyCount, conGroup.NamespaceName, conGroup.ContainerGroupName, appArmorProfile)
		}
	}
}
