package enforcer

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// == //

func allowedProcesses(secPolicy tp.SecurityPolicy) []string {
	processWhiteList := []string{}

	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if len(path.FromSource) > 0 {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				processWhiteList = append(processWhiteList, line)
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  audit %s ix,\n", path.Path)
				processWhiteList = append(processWhiteList, line)
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if len(dir.FromSource) > 0 {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				processWhiteList = append(processWhiteList, line)
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
				processWhiteList = append(processWhiteList, line)
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				processWhiteList = append(processWhiteList, line)
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
				processWhiteList = append(processWhiteList, line)
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			if pat.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
				processWhiteList = append(processWhiteList, line)
			} else { // !pat.OwnerOnly
				line := fmt.Sprintf("  audit %s* ix,\n", pat.Pattern)
				processWhiteList = append(processWhiteList, line)
			}
		}
	}

	return processWhiteList
}

func allowedFiles(secPolicy tp.SecurityPolicy) []string {
	fileWhiteList := []string{}

	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if len(path.FromSource) > 0 {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				fileWhiteList = append(fileWhiteList, line)
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  audit %s r,\n", path.Path)
				fileWhiteList = append(fileWhiteList, line)
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				fileWhiteList = append(fileWhiteList, line)
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  audit %s rw,\n", path.Path)
				fileWhiteList = append(fileWhiteList, line)
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if len(dir.FromSource) > 0 {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					fileWhiteList = append(fileWhiteList, line)
				} else {
					line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					fileWhiteList = append(fileWhiteList, line)
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
					fileWhiteList = append(fileWhiteList, line)
				} else {
					line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
					fileWhiteList = append(fileWhiteList, line)
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					fileWhiteList = append(fileWhiteList, line)
				} else {
					line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					fileWhiteList = append(fileWhiteList, line)
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
					fileWhiteList = append(fileWhiteList, line)
				} else {
					line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
					fileWhiteList = append(fileWhiteList, line)
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
				fileWhiteList = append(fileWhiteList, line)
			} else if pat.ReadOnly && !pat.OwnerOnly {
				line := fmt.Sprintf("  audit %s r,\n", pat.Pattern)
				fileWhiteList = append(fileWhiteList, line)
			} else if !pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
				fileWhiteList = append(fileWhiteList, line)
			} else { // !pat.ReadOnly && !pat.OwnerOnly
				line := fmt.Sprintf("  audit %s rw,\n", pat.Pattern)
				fileWhiteList = append(fileWhiteList, line)
			}
		}
	}

	return fileWhiteList
}

func allowedNetworks(secPolicy tp.SecurityPolicy) []string {
	networkWhiteList := []string{}

	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.FromSource) > 0 {
				continue
			}

			line := fmt.Sprintf("  network %s,\n", proto.Protocol)
			networkWhiteList = append(networkWhiteList, line)
		}
	}

	return networkWhiteList
}

func allowedCapabilities(secPolicy tp.SecurityPolicy) []string {
	capabilityWhiteList := []string{}

	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.FromSource) > 0 {
				continue
			}

			line := fmt.Sprintf("  capability %s,\n", cap.Capability)
			capabilityWhiteList = append(capabilityWhiteList, line)
		}
	}

	return capabilityWhiteList
}

//

func blockedProcesses(secPolicy tp.SecurityPolicy) []string {
	processBlackList := []string{}

	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if len(path.FromSource) > 0 {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				processBlackList = append(processBlackList, line)
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
				processBlackList = append(processBlackList, line)
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if len(dir.FromSource) > 0 {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				processBlackList = append(processBlackList, line)
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
				processBlackList = append(processBlackList, line)
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				processBlackList = append(processBlackList, line)
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
				processBlackList = append(processBlackList, line)
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			if pat.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
				processBlackList = append(processBlackList, line)
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  audit deny %s x,\n", pat.Pattern)
				processBlackList = append(processBlackList, line)
			}
		}
	}

	return processBlackList
}

func blockedFiles(secPolicy tp.SecurityPolicy) []string {
	fileBlackList := []string{}

	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if len(path.FromSource) > 0 {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				fileBlackList = append(fileBlackList, line)
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  audit deny %s w,\n", path.Path)
				fileBlackList = append(fileBlackList, line)
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				fileBlackList = append(fileBlackList, line)
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
				fileBlackList = append(fileBlackList, line)
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if len(dir.FromSource) > 0 {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				} else {
					line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny %s{*,**} w,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				} else {
					line := fmt.Sprintf("  audit deny %s* w,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				} else {
					line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				} else {
					line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
				fileBlackList = append(fileBlackList, line)
			} else if pat.ReadOnly && !pat.OwnerOnly {
				line := fmt.Sprintf("  audit deny %s w,\n", pat.Pattern)
				fileBlackList = append(fileBlackList, line)
			} else if !pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
				fileBlackList = append(fileBlackList, line)
			} else { // !pat.ReadOnly && !pat.OwnerOnly
				line := fmt.Sprintf("  audit deny %s rw,\n", pat.Pattern)
				fileBlackList = append(fileBlackList, line)
			}
		}
	}

	return fileBlackList
}

func blockedNetworks(secPolicy tp.SecurityPolicy) []string {
	networkBlackList := []string{}

	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.FromSource) > 0 {
				continue
			}

			line := fmt.Sprintf("  deny network %s,\n", proto.Protocol)
			networkBlackList = append(networkBlackList, line)
		}
	}

	return networkBlackList
}

func blockedCapabilities(secPolicy tp.SecurityPolicy) []string {
	capabilityBlackList := []string{}

	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.FromSource) > 0 {
				continue
			}

			line := fmt.Sprintf("  deny capability %s,\n", cap.Capability)
			capabilityBlackList = append(capabilityBlackList, line)
		}
	}

	return capabilityBlackList
}

// == //

func allowedProcessesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string) {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if len(path.FromSource) == 0 {
				continue
			}

			for _, src := range path.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
					line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !path.OwnerOnly
					line := fmt.Sprintf("  audit %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if len(dir.FromSource) == 0 {
				continue
			}

			for _, src := range dir.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
					line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if dir.Recursive && !dir.OwnerOnly {
					line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if !dir.Recursive && dir.OwnerOnly {
					line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !dir.Recursive && !dir.OwnerOnly
					line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func allowedFilesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string) {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if len(path.FromSource) == 0 {
				continue
			}

			for _, src := range path.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
					line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if path.ReadOnly && !path.OwnerOnly {
					line := fmt.Sprintf("  audit %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if !path.ReadOnly && path.OwnerOnly {
					line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !path.ReadOnly && !path.OwnerOnly
					line := fmt.Sprintf("  audit %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if len(dir.FromSource) == 0 {
				continue
			}

			for _, src := range dir.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
						line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else if dir.ReadOnly && !dir.OwnerOnly {
					if dir.Recursive {
						line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else if !dir.ReadOnly && dir.OwnerOnly {
					if dir.Recursive {
						line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else { // !dir.ReadOnly && !dir.OwnerOnly
					if dir.Recursive {
						line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			}
		}
	}
}

func allowedNetworksFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string) {
	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.FromSource) == 0 {
				continue
			}

			for _, src := range proto.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
}

func allowedCapabilitiesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string) {
	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.FromSource) == 0 {
				continue
			}

			for _, src := range cap.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
}

func blockedProcessesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string) {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if len(path.FromSource) == 0 {
				continue
			}

			for _, src := range path.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
					line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !path.OwnerOnly
					line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if len(dir.FromSource) == 0 {
				continue
			}

			for _, src := range dir.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
					line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if dir.Recursive && !dir.OwnerOnly {
					line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if !dir.Recursive && dir.OwnerOnly {
					line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !dir.Recursive && !dir.OwnerOnly
					line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func blockedFilesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string) {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if len(path.FromSource) == 0 {
				continue
			}

			for _, src := range path.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
					line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if path.ReadOnly && !path.OwnerOnly {
					line := fmt.Sprintf("  audit deny %s w,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if !path.ReadOnly && path.OwnerOnly {
					line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !path.ReadOnly && !path.OwnerOnly
					line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if len(dir.FromSource) == 0 {
				continue
			}

			for _, src := range dir.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
						line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else if dir.ReadOnly && !dir.OwnerOnly {
					if dir.Recursive {
						line := fmt.Sprintf("  audit deny %s{*,**} w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  audit deny %s* w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else if !dir.ReadOnly && dir.OwnerOnly {
					if dir.Recursive {
						line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else { // !dir.ReadOnly && !dir.OwnerOnly
					if dir.Recursive {
						line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				}
			}
		}
	}
}

func blockedNetworksFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string) {
	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.FromSource) == 0 {
				continue
			}

			for _, src := range proto.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
}

func blockedCapabilitiesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string) {
	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.FromSource) == 0 {
				continue
			}

			for _, src := range cap.FromSource {
				source := ""

				if len(src.Path) > 0 {
					source = fmt.Sprintf("%s", src.Path)
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
}

// == //

// GenerateProfileHead Function
func GenerateProfileHead(processWhiteList, fileWhiteList, networkWhiteList, capabilityWhiteList []string) string {
	profileHead := "  #include <abstractions/base>\n"
	profileHead = profileHead + "  umount,\n"

	if len(processWhiteList) == 0 && len(fileWhiteList) == 0 {
		profileHead = profileHead + "  file,\n"
	}

	if len(networkWhiteList) == 0 {
		profileHead = profileHead + "  network,\n"
	}

	if len(capabilityWhiteList) == 0 {
		profileHead = profileHead + "  capability,\n"
	}

	return profileHead
}

// GenerateProfileFoot Function
func GenerateProfileFoot() string {
	profileFoot := "  /lib/x86_64-linux-gnu/{*,**} r,\n"
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
func GenerateProfileBody(oldContentsPreMid, oldConetntsMidPost []string, securityPolicies []tp.SecurityPolicy) (int, string) {
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

	// preparation - global

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Audit" || secPolicy.Spec.Action == "Allow" || secPolicy.Spec.Action == "AllowWithAudit" {
			whiteList := []string{}

			// process
			whiteList = allowedProcesses(secPolicy)

			for _, line := range whiteList {
				if !kl.ContainsElement(processWhiteList, line) {
					processWhiteList = append(processWhiteList, line)
				}
			}

			// file
			whiteList = allowedFiles(secPolicy)

			for _, line := range whiteList {
				if !kl.ContainsElement(fileWhiteList, line) {
					fileWhiteList = append(fileWhiteList, line)
				}
			}

			// network
			whiteList = allowedNetworks(secPolicy)

			for _, line := range whiteList {
				if !kl.ContainsElement(networkWhiteList, line) {
					networkWhiteList = append(networkWhiteList, line)
				}
			}

			// capabilities
			whiteList = allowedCapabilities(secPolicy)

			for _, line := range whiteList {
				if !kl.ContainsElement(capabilityWhiteList, line) {
					capabilityWhiteList = append(capabilityWhiteList, line)
				}
			}
		}
	}

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Block" || secPolicy.Spec.Action == "BlockWithAudit" {
			blackList := []string{}

			// process
			blackList = blockedProcesses(secPolicy)

			for _, line := range blackList {
				if !kl.ContainsElement(processBlackList, line) {
					processBlackList = append(processBlackList, line)
				}
			}

			// file
			blackList = blockedFiles(secPolicy)

			for _, line := range blackList {
				if !kl.ContainsElement(fileBlackList, line) {
					fileBlackList = append(fileBlackList, line)
				}
			}

			// network
			blackList = blockedNetworks(secPolicy)

			for _, line := range blackList {
				if !kl.ContainsElement(networkBlackList, line) {
					networkBlackList = append(networkBlackList, line)
				}
			}

			// capabilities
			blackList = blockedCapabilities(secPolicy)

			for _, line := range blackList {
				if !kl.ContainsElement(capabilityBlackList, line) {
					capabilityBlackList = append(capabilityBlackList, line)
				}
			}
		}
	}

	// preparation - fromSource

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Audit" || secPolicy.Spec.Action == "Allow" || secPolicy.Spec.Action == "AllowWithAudit" {
			// process
			allowedProcessesFromSource(secPolicy, fromSources)

			// file
			allowedFilesFromSource(secPolicy, fromSources)

			// network
			allowedNetworksFromSource(secPolicy, fromSources)

			// capabilities
			allowedCapabilitiesFromSource(secPolicy, fromSources)
		}
	}

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Block" || secPolicy.Spec.Action == "BlockWithAudit" {
			// process
			blockedProcessesFromSource(secPolicy, fromSources)

			// file
			blockedFilesFromSource(secPolicy, fromSources)

			// network
			blockedNetworksFromSource(secPolicy, fromSources)

			// capabilities
			blockedCapabilitiesFromSource(secPolicy, fromSources)
		}
	}

	// head

	profileHead := "  ## == PRE START == ##\n"

	profileHead = profileHead + GenerateProfileHead(processWhiteList, fileWhiteList, networkWhiteList, capabilityWhiteList)

	profileHead = profileHead + "  ## == PRE END == ##\n"

	// body

	profileBody := ""

	// body - from source

	bodyFromSource := ""

	for source, lines := range fromSources {
		bodyFromSource = bodyFromSource + fmt.Sprintf("  %s cx,\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("  profile %s {\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("  %s r,\n", source)

		bodyFromSource = bodyFromSource + fmt.Sprintf("  ## == PRE START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + "  #include <abstractions/base>\n"
		bodyFromSource = bodyFromSource + "  umount,\n"

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

		if file && len(processWhiteList) == 0 && len(fileWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "  file,\n"
		}

		if network && len(networkWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "  network,\n"
		}

		if capability && len(capabilityWhiteList) == 0 {
			bodyFromSource = bodyFromSource + "  capability,\n"
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("  ## == PRE END (%s) == ##\n", source)
		bodyFromSource = bodyFromSource + profileBody
		bodyFromSource = bodyFromSource + fmt.Sprintf("  ## == POLICY START (%s) == ##\n\n", source)

		//

		for _, line := range lines {
			bodyFromSource = bodyFromSource + line
		}

		//

		bodyFromSource = bodyFromSource + fmt.Sprintf("  ## == POLICY END (%s) == ##\n\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("  ## == POST START (%s) == ##\n", source)

		bodyFromSource = bodyFromSource + GenerateProfileFoot()

		bodyFromSource = bodyFromSource + fmt.Sprintf("  ## == POST END (%s) == ##\n", source)
		bodyFromSource = bodyFromSource + "  }\n"
	}

	for _, source := range fromSources {
		count = count + len(source)
	}

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

	// body - together

	profileBody = "  ## == POLICY START == ##\n" + bodyFromSource + profileBody + "  ## == POLICY END == ##\n"

	// foot

	profileFoot := "  ## == POST START == ##\n" + GenerateProfileFoot() + "  ## == POST END == ##\n"

	// finalization

	profile := profileHead

	for _, preMid := range oldContentsPreMid {
		profile = profile + preMid
	}

	profile = profile + profileBody

	for _, midPost := range oldConetntsMidPost {
		profile = profile + midPost
	}

	profile = profile + profileFoot

	return count, profile
}

// == //

// GenerateAppArmorProfile Function
func (ae *AppArmorEnforcer) GenerateAppArmorProfile(appArmorProfile string, securityPolicies []tp.SecurityPolicy) (int, string, bool) {
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
		} else if pos == "POST" {
			//
		} else if pos == "FOOT" {
			oldContentsFoot = append(oldContentsFoot, line+"\n")
		}
	}

	file.Close()

	// generate a profile body

	count, profileBody := GenerateProfileBody(oldContentsPreMid, oldConetntsMidPost, securityPolicies)

	// generate a new profile

	newProfile := ""

	// head

	for _, head := range oldContentsHead {
		newProfile = newProfile + head
	}

	// body

	newProfile = newProfile + profileBody

	// foot

	for _, foot := range oldContentsFoot {
		newProfile = newProfile + foot
	}

	if newProfile != oldProfile {
		return count, newProfile, true
	}

	return 0, "", false
}
