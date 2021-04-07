package enforcer

import (
	"fmt"
	"strings"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// == //

// no allowedProcesses for hosts

// no allowedFiles for hosts

// no allowedNetworks for hosts

// no allowedCapabilities for hosts

//

func auditedHostProcesses(secPolicy tp.HostSecurityPolicy) []string {
	processAuditList := []string{}

	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if len(path.FromSource) > 0 {
				continue
			}

			if path.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				processAuditList = append(processAuditList, line)
			} else { // !path.OwnerOnly
				// line := fmt.Sprintf("  audit %s ix,\n", path.Path)
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				processAuditList = append(processAuditList, line)
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if len(dir.FromSource) > 0 {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				processAuditList = append(processAuditList, line)
			} else if dir.Recursive && !dir.OwnerOnly {
				// line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				processAuditList = append(processAuditList, line)
			} else if !dir.Recursive && dir.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				processAuditList = append(processAuditList, line)
			} else { // !dir.Recursive && !dir.OwnerOnly
				// line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				processAuditList = append(processAuditList, line)
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			if pat.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
				line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
				processAuditList = append(processAuditList, line)
			} else { // !pat.OwnerOnly
				// line := fmt.Sprintf("  audit %s* ix,\n", pat.Pattern)
				line := fmt.Sprintf("  %s* ix,\n", pat.Pattern)
				processAuditList = append(processAuditList, line)
			}
		}
	}

	return processAuditList
}

func auditedHostFiles(secPolicy tp.HostSecurityPolicy) []string {
	fileAuditList := []string{}

	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if len(path.FromSource) > 0 {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				fileAuditList = append(fileAuditList, line)
			} else if path.ReadOnly && !path.OwnerOnly {
				// line := fmt.Sprintf("  audit %s r,\n", path.Path)
				line := fmt.Sprintf("  %s r,\n", path.Path)
				fileAuditList = append(fileAuditList, line)
			} else if !path.ReadOnly && path.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				fileAuditList = append(fileAuditList, line)
			} else { // !path.ReadOnly && !path.OwnerOnly
				// line := fmt.Sprintf("  audit %s rw,\n", path.Path)
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				fileAuditList = append(fileAuditList, line)
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
					// line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					fileAuditList = append(fileAuditList, line)
				} else {
					// line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					fileAuditList = append(fileAuditList, line)
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					// line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					fileAuditList = append(fileAuditList, line)
				} else {
					// line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					fileAuditList = append(fileAuditList, line)
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					// line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					fileAuditList = append(fileAuditList, line)
				} else {
					// line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					fileAuditList = append(fileAuditList, line)
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					// line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					fileAuditList = append(fileAuditList, line)
				} else {
					// line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
					line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
					fileAuditList = append(fileAuditList, line)
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.ReadOnly && pat.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
				line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
				fileAuditList = append(fileAuditList, line)
			} else if pat.ReadOnly && !pat.OwnerOnly {
				// line := fmt.Sprintf("  audit %s r,\n", pat.Pattern)
				line := fmt.Sprintf("  %s r,\n", pat.Pattern)
				fileAuditList = append(fileAuditList, line)
			} else if !pat.ReadOnly && pat.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
				line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
				fileAuditList = append(fileAuditList, line)
			} else { // !pat.ReadOnly && !pat.OwnerOnly
				// line := fmt.Sprintf("  audit %s rw,\n", pat.Pattern)
				line := fmt.Sprintf("  %s rw,\n", pat.Pattern)
				fileAuditList = append(fileAuditList, line)
			}
		}
	}

	return fileAuditList
}

//

func blockedHostProcesses(secPolicy tp.HostSecurityPolicy) []string {
	processBlackList := []string{}

	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if len(path.FromSource) > 0 {
				continue
			}

			if path.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				processBlackList = append(processBlackList, line)
			} else { // !path.OwnerOnly
				// line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
				line := fmt.Sprintf("  deny %s x,\n", path.Path)
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
				// line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				processBlackList = append(processBlackList, line)
			} else if dir.Recursive && !dir.OwnerOnly {
				// line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
				line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
				processBlackList = append(processBlackList, line)
			} else if !dir.Recursive && dir.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				processBlackList = append(processBlackList, line)
			} else { // !dir.Recursive && !dir.OwnerOnly
				// line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
				line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
				processBlackList = append(processBlackList, line)
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			if pat.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
				line := fmt.Sprintf("  owner %s ix,\n", pat.Pattern)
				processBlackList = append(processBlackList, line)
			} else { // !path.OwnerOnly
				// line := fmt.Sprintf("  audit deny %s x,\n", pat.Pattern)
				line := fmt.Sprintf("  deny %s x,\n", pat.Pattern)
				processBlackList = append(processBlackList, line)
			}
		}
	}

	return processBlackList
}

func blockedHostFiles(secPolicy tp.HostSecurityPolicy) []string {
	fileBlackList := []string{}

	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if len(path.FromSource) > 0 {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				fileBlackList = append(fileBlackList, line)
			} else if path.ReadOnly && !path.OwnerOnly {
				// line := fmt.Sprintf("  audit deny %s w,\n", path.Path)
				line := fmt.Sprintf("  deny %s w,\n", path.Path)
				fileBlackList = append(fileBlackList, line)
			} else if !path.ReadOnly && path.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				fileBlackList = append(fileBlackList, line)
			} else { // !path.ReadOnly && !path.OwnerOnly
				// line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
				line := fmt.Sprintf("  deny %s rw,\n", path.Path)
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
					// line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				} else {
					// line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					// line := fmt.Sprintf("  audit deny %s{*,**} w,\n", dir.Directory)
					line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				} else {
					// line := fmt.Sprintf("  audit deny %s* w,\n", dir.Directory)
					line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					// line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				} else {
					// line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					// line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
					line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				} else {
					// line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
					line := fmt.Sprintf("  deny %s* rw,\n", dir.Directory)
					fileBlackList = append(fileBlackList, line)
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.ReadOnly && pat.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
				line := fmt.Sprintf("  owner %s r,\n", pat.Pattern)
				fileBlackList = append(fileBlackList, line)
			} else if pat.ReadOnly && !pat.OwnerOnly {
				// line := fmt.Sprintf("  audit deny %s w,\n", pat.Pattern)
				line := fmt.Sprintf("  deny %s w,\n", pat.Pattern)
				fileBlackList = append(fileBlackList, line)
			} else if !pat.ReadOnly && pat.OwnerOnly {
				// line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
				line := fmt.Sprintf("  owner %s rw,\n", pat.Pattern)
				fileBlackList = append(fileBlackList, line)
			} else { // !pat.ReadOnly && !pat.OwnerOnly
				// line := fmt.Sprintf("  audit deny %s rw,\n", pat.Pattern)
				line := fmt.Sprintf("  deny %s rw,\n", pat.Pattern)
				fileBlackList = append(fileBlackList, line)
			}
		}
	}

	return fileBlackList
}

// no blockedNetworks for hosts

// no blockedCapabilities for hosts

// == //

func allowedHostProcessesFromSource(secPolicy tp.HostSecurityPolicy, fromSources map[string][]string) {
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
					// line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					line := fmt.Sprintf("  owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !path.OwnerOnly
					// line := fmt.Sprintf("  audit %s ix,\n", path.Path)
					line := fmt.Sprintf("  %s ix,\n", path.Path)
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
					// line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if dir.Recursive && !dir.OwnerOnly {
					// line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
					line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if !dir.Recursive && dir.OwnerOnly {
					// line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !dir.Recursive && !dir.OwnerOnly
					// line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
					line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func allowedHostFilesFromSource(secPolicy tp.HostSecurityPolicy, fromSources map[string][]string) {
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
					// line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					line := fmt.Sprintf("  owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if path.ReadOnly && !path.OwnerOnly {
					// line := fmt.Sprintf("  audit %s r,\n", path.Path)
					line := fmt.Sprintf("  %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if !path.ReadOnly && path.OwnerOnly {
					// line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					line := fmt.Sprintf("  owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !path.ReadOnly && !path.OwnerOnly
					// line := fmt.Sprintf("  audit %s rw,\n", path.Path)
					line := fmt.Sprintf("  %s rw,\n", path.Path)
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
						// line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						// line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else if dir.ReadOnly && !dir.OwnerOnly {
					if dir.Recursive {
						// line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
						line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						// line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
						line := fmt.Sprintf("  %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else if !dir.ReadOnly && dir.OwnerOnly {
					if dir.Recursive {
						// line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						// line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else { // !dir.ReadOnly && !dir.OwnerOnly
					if dir.Recursive {
						// line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
						line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						// line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
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

func allowedHostNetworksFromSource(secPolicy tp.HostSecurityPolicy, fromSources map[string][]string) {
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

func allowedHostCapabilitiesFromSource(secPolicy tp.HostSecurityPolicy, fromSources map[string][]string) {
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

//

func blockedHostProcessesFromSource(secPolicy tp.HostSecurityPolicy, fromSources map[string][]string) {
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
					// line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
					line := fmt.Sprintf("  owner %s ix,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !path.OwnerOnly
					// line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
					line := fmt.Sprintf("  deny %s x,\n", path.Path)
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
					// line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if dir.Recursive && !dir.OwnerOnly {
					// line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
					line := fmt.Sprintf("  deny %s{*,**} x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if !dir.Recursive && dir.OwnerOnly {
					// line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
					line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !dir.Recursive && !dir.OwnerOnly
					// line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
					line := fmt.Sprintf("  deny %s* x,\n", dir.Directory)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				}
			}
		}
	}
}

func blockedHostFilesFromSource(secPolicy tp.HostSecurityPolicy, fromSources map[string][]string) {
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
					// line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
					line := fmt.Sprintf("  owner %s r,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if path.ReadOnly && !path.OwnerOnly {
					// line := fmt.Sprintf("  audit deny %s w,\n", path.Path)
					line := fmt.Sprintf("  deny %s w,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else if !path.ReadOnly && path.OwnerOnly {
					// line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
					line := fmt.Sprintf("  owner %s rw,\n", path.Path)
					if !kl.ContainsElement(fromSources[source], line) {
						fromSources[source] = append(fromSources[source], line)
					}
				} else { // !path.ReadOnly && !path.OwnerOnly
					// line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
					line := fmt.Sprintf("  deny %s rw,\n", path.Path)
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
						// line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
						line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						// line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
						line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else if dir.ReadOnly && !dir.OwnerOnly {
					if dir.Recursive {
						// line := fmt.Sprintf("  audit deny %s{*,**} w,\n", dir.Directory)
						line := fmt.Sprintf("  deny %s{*,**} w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						// line := fmt.Sprintf("  audit deny %s* w,\n", dir.Directory)
						line := fmt.Sprintf("  deny %s* w,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else if !dir.ReadOnly && dir.OwnerOnly {
					if dir.Recursive {
						// line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
						line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						// line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
						line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					}
				} else { // !dir.ReadOnly && !dir.OwnerOnly
					if dir.Recursive {
						// line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
						line := fmt.Sprintf("  deny %s{*,**} rw,\n", dir.Directory)
						if !kl.ContainsElement(fromSources[source], line) {
							fromSources[source] = append(fromSources[source], line)
						}
					} else {
						// line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
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

func blockedHostNetworksFromSource(secPolicy tp.HostSecurityPolicy, fromSources map[string][]string) {
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

func blockedHostCapabilitiesFromSource(secPolicy tp.HostSecurityPolicy, fromSources map[string][]string) {
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
		"  /usr/bin/runc Ux,\n" +
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
func GenerateHostProfileBody(secPolicies []tp.HostSecurityPolicy) (int, string) {
	// preparation

	count := 0

	processAuditList := []string{}
	processBlackList := []string{}

	fileAuditList := []string{}
	fileBlackList := []string{}

	fromSources := map[string][]string{}

	// preparation - global

	for _, secPolicy := range secPolicies {
		if secPolicy.Spec.Action == "Audit" {
			auditList := []string{}

			// process
			auditList = auditedHostProcesses(secPolicy)

			for _, line := range auditList {
				if !kl.ContainsElement(processAuditList, line) {
					processAuditList = append(processAuditList, line)
				}
			}

			// file
			auditList = auditedHostFiles(secPolicy)

			for _, line := range auditList {
				if !kl.ContainsElement(fileAuditList, line) {
					fileAuditList = append(fileAuditList, line)
				}
			}
		}
	}

	for _, secPolicy := range secPolicies {
		if secPolicy.Spec.Action == "Block" || secPolicy.Spec.Action == "BlockWithAudit" {
			blackList := []string{}

			// process
			blackList = blockedHostProcesses(secPolicy)

			for _, line := range blackList {
				if !kl.ContainsElement(processBlackList, line) {
					processBlackList = append(processBlackList, line)
				}
			}

			// file
			blackList = blockedHostFiles(secPolicy)

			for _, line := range blackList {
				if !kl.ContainsElement(fileBlackList, line) {
					fileBlackList = append(fileBlackList, line)
				}
			}
		}
	}

	// preparation - fromSource

	for _, secPolicy := range secPolicies {
		if secPolicy.Spec.Action == "Audit" || secPolicy.Spec.Action == "Allow" || secPolicy.Spec.Action == "AllowWithAudit" {
			// process
			allowedHostProcessesFromSource(secPolicy, fromSources)

			// file
			allowedHostFilesFromSource(secPolicy, fromSources)

			// network
			allowedHostNetworksFromSource(secPolicy, fromSources)

			// capabilities
			allowedHostCapabilitiesFromSource(secPolicy, fromSources)
		}
	}

	for _, secPolicy := range secPolicies {
		if secPolicy.Spec.Action == "Block" || secPolicy.Spec.Action == "BlockWithAudit" {
			// process
			blockedHostProcessesFromSource(secPolicy, fromSources)

			// file
			blockedHostFilesFromSource(secPolicy, fromSources)

			// network
			blockedHostNetworksFromSource(secPolicy, fromSources)

			// capabilities
			blockedHostCapabilitiesFromSource(secPolicy, fromSources)
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

	// finalization

	profile := bodyFromSource + profileBody

	return count, profile
}

// GenerateAppArmorHostProfile Function
func (ae *AppArmorEnforcer) GenerateAppArmorHostProfile(secPolicies []tp.HostSecurityPolicy) (int, string, bool) {

	// generate a profile body

	count, profileBody := GenerateHostProfileBody(secPolicies)

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
