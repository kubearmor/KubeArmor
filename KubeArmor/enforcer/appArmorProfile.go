package enforcer

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// == //

func allowedProcesses(secPolicy tp.SecurityPolicy, allowLines []string, allowCount int) ([]string, int, bool) {
	oldCount := allowCount

	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if path.FromSource.Path != "" || path.FromSource.Directory != "" {
				continue
			}

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
			if dir.FromSource.Path != "" || dir.FromSource.Directory != "" {
				continue
			}

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
			if path.FromSource.Path != "" || path.FromSource.Directory != "" {
				continue
			}

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
			if dir.FromSource.Path != "" || dir.FromSource.Directory != "" {
				continue
			}

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
			if path.FromSource.Path != "" || path.FromSource.Directory != "" {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				auditLines = append(auditLines, line)
				auditCount++
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  audit %s ix,\n", path.Path)
				auditLines = append(auditLines, line)
				auditCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.FromSource.Path != "" || dir.FromSource.Directory != "" {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				auditLines = append(auditLines, line)
				auditCount++
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
				auditLines = append(auditLines, line)
				auditCount++
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				auditLines = append(auditLines, line)
				auditCount++
			} else { // !dir.Recursive && !dir.OwnerOnly
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

			if pat.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s ix,\n", pat.Pattern)
				auditLines = append(auditLines, line)
				auditCount++
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  audit %s ix,\n", pat.Pattern)
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
			if path.FromSource.Path != "" || path.FromSource.Directory != "" {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				auditLines = append(auditLines, line)
				auditCount++
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  audit %s r,\n", path.Path)
				auditLines = append(auditLines, line)
				auditCount++
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				auditLines = append(auditLines, line)
				auditCount++
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  audit %s rw,\n", path.Path)
				auditLines = append(auditLines, line)
				auditCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.FromSource.Path != "" || dir.FromSource.Directory != "" {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit owner %s{*,**} r,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				} else {
					line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				} else {
					line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				} else {
					line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				} else {
					line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
					auditLines = append(auditLines, line)
					auditCount++
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s r,\n", pat.Pattern)
				auditLines = append(auditLines, line)
				auditCount++
			} else if pat.ReadOnly && !pat.OwnerOnly {
				line := fmt.Sprintf("  audit %s r,\n", pat.Pattern)
				auditLines = append(auditLines, line)
				auditCount++
			} else if !pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s rw,\n", pat.Pattern)
				auditLines = append(auditLines, line)
				auditCount++
			} else { // !pat.ReadOnly && !pat.OwnerOnly
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
			if path.FromSource.Path != "" || path.FromSource.Directory != "" {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s x,\n", path.Path)
				denyLines = append(denyLines, line)
				denyCount++
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
				denyLines = append(denyLines, line)
				denyCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.FromSource.Path != "" || dir.FromSource.Directory != "" {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s{*,**} x,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s* x,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
				denyLines = append(denyLines, line)
				denyCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.Process.MatchPatterns {
			if pat.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s x,\n", pat.Pattern)
				denyLines = append(denyLines, line)
				denyCount++
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  audit deny %s x,\n", pat.Pattern)
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
			if path.FromSource.Path != "" || path.FromSource.Directory != "" {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s r,\n", path.Path)
				denyLines = append(denyLines, line)
				denyCount++
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  audit deny %s r,\n", path.Path)
				denyLines = append(denyLines, line)
				denyCount++
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s rw,\n", path.Path)
				denyLines = append(denyLines, line)
				denyCount++
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
				denyLines = append(denyLines, line)
				denyCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.FromSource.Path != "" || dir.FromSource.Directory != "" {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny owner %s{*,**} r,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				} else {
					line := fmt.Sprintf("  audit deny owner %s* r,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny %s{*,**} r,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				} else {
					line := fmt.Sprintf("  audit deny %s* r,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny owner %s{*,**} rw,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				} else {
					line := fmt.Sprintf("  audit deny owner %s* rw,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				} else {
					line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
					denyLines = append(denyLines, line)
					denyCount++
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for _, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s r,\n", pat.Pattern)
				denyLines = append(denyLines, line)
				denyCount++
			} else if pat.ReadOnly && !pat.OwnerOnly {
				line := fmt.Sprintf("  audit deny %s r,\n", pat.Pattern)
				denyLines = append(denyLines, line)
				denyCount++
			} else if !pat.ReadOnly && pat.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s rw,\n", pat.Pattern)
				denyLines = append(denyLines, line)
				denyCount++
			} else { // !pat.ReadOnly && !pat.OwnerOnly
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

// == //

func allowedProcessesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string, allowCount int) int {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if path.FromSource.Path == "" && path.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(path.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", path.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(path.FromSource.Directory) > 0 {
				if path.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  owner %s ix,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  %s ix,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.FromSource.Path == "" && dir.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(dir.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", dir.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(dir.FromSource.Directory) > 0 {
				if dir.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s{*,**} ix,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  %s{*,**} ix,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  owner %s* ix,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  %s* ix,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			}
		}
	}

	return allowCount
}

func allowedFilesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string, allowCount int) int {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if path.FromSource.Path == "" && path.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(path.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", path.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(path.FromSource.Directory) > 0 {
				if path.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s r,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  %s r,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  owner %s rw,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  %s rw,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				allowCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.FromSource.Path == "" && dir.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(dir.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", dir.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(dir.FromSource.Directory) > 0 {
				if dir.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					allowCount++
				} else {
					line := fmt.Sprintf("  owner %s* r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					allowCount++
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					allowCount++
				} else {
					line := fmt.Sprintf("  %s* r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					allowCount++
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  owner %s{*,**} rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					allowCount++
				} else {
					line := fmt.Sprintf("  owner %s* rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					allowCount++
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  %s{*,**} rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					allowCount++
				} else {
					line := fmt.Sprintf("  %s* rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					allowCount++
				}
			}
		}
	}

	return allowCount
}

func auditedProcessesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string, auditCount int) int {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if path.FromSource.Path == "" && path.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(path.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", path.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(path.FromSource.Directory) > 0 {
				if path.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s ix,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  audit %s ix,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.FromSource.Path == "" && dir.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(dir.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", dir.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(dir.FromSource.Directory) > 0 {
				if dir.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s{*,**} ix,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  audit %s{*,**} ix,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s* ix,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  audit %s* ix,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			}
		}
	}

	return auditCount
}

func auditedFilesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string, auditCount int) int {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if path.FromSource.Path == "" && path.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(path.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", path.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(path.FromSource.Directory) > 0 {
				if path.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s r,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  audit %s r,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit owner %s rw,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  audit %s rw,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				auditCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.FromSource.Path == "" && dir.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(dir.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", dir.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(dir.FromSource.Directory) > 0 {
				if dir.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", dir.FromSource.Path)
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
					fromSources[source] = append(fromSources[source], line)
					auditCount++
				} else {
					line := fmt.Sprintf("  audit owner %s* r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					auditCount++
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit %s{*,**} r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					auditCount++
				} else {
					line := fmt.Sprintf("  audit %s* r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					auditCount++
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit owner %s{*,**} rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					auditCount++
				} else {
					line := fmt.Sprintf("  audit owner %s* rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					auditCount++
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  audit %s{*,**} rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					auditCount++
				} else {
					line := fmt.Sprintf("  audit %s* rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					auditCount++
				}
			}
		}
	}

	return auditCount
}

func blockedProcessesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string, denyCount int) int {
	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			if path.FromSource.Path == "" && path.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(path.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", path.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(path.FromSource.Directory) > 0 {
				if path.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s x,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			} else { // !path.OwnerOnly
				line := fmt.Sprintf("  audit deny %s x,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.FromSource.Path == "" && dir.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(dir.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", dir.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(dir.FromSource.Directory) > 0 {
				if dir.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s{*,**} x,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			} else if dir.Recursive && !dir.OwnerOnly {
				line := fmt.Sprintf("  audit deny %s{*,**} x,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			} else if !dir.Recursive && dir.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s* x,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			} else { // !dir.Recursive && !dir.OwnerOnly
				line := fmt.Sprintf("  audit deny %s* x,\n", dir.Directory)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			}
		}
	}

	return denyCount
}

func blockedFilesFromSource(secPolicy tp.SecurityPolicy, fromSources map[string][]string, denyCount int) int {
	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for _, path := range secPolicy.Spec.File.MatchPaths {
			if path.FromSource.Path == "" && path.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(path.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", path.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(path.FromSource.Directory) > 0 {
				if path.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", path.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s r,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			} else if path.ReadOnly && !path.OwnerOnly {
				line := fmt.Sprintf("  audit deny %s r,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			} else if !path.ReadOnly && path.OwnerOnly {
				line := fmt.Sprintf("  audit deny owner %s rw,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			} else { // !path.ReadOnly && !path.OwnerOnly
				line := fmt.Sprintf("  audit deny %s rw,\n", path.Path)
				fromSources[source] = append(fromSources[source], line)
				denyCount++
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.FromSource.Path == "" && dir.FromSource.Directory == "" {
				continue
			}

			source := ""

			if len(dir.FromSource.Path) > 0 {
				source = fmt.Sprintf("%s", dir.FromSource.Path)
				if _, ok := fromSources[source]; !ok {
					fromSources[source] = []string{}
				}
			} else if len(dir.FromSource.Directory) > 0 {
				if dir.FromSource.Recursive {
					source = fmt.Sprintf("%s{*,**}", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				} else {
					source = fmt.Sprintf("%s*", dir.FromSource.Path)
					if _, ok := fromSources[source]; !ok {
						fromSources[source] = []string{}
					}
				}
			} else {
				continue
			}

			if dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny owner %s{*,**} r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					denyCount++
				} else {
					line := fmt.Sprintf("  audit deny owner %s* r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					denyCount++
				}
			} else if dir.ReadOnly && !dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny %s{*,**} r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					denyCount++
				} else {
					line := fmt.Sprintf("  audit deny %s* r,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					denyCount++
				}
			} else if !dir.ReadOnly && dir.OwnerOnly {
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny owner %s{*,**} rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					denyCount++
				} else {
					line := fmt.Sprintf("  audit deny owner %s* rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					denyCount++
				}
			} else { // !dir.ReadOnly && !dir.OwnerOnly
				if dir.Recursive {
					line := fmt.Sprintf("  audit deny %s{*,**} rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					denyCount++
				} else {
					line := fmt.Sprintf("  audit deny %s* rw,\n", dir.Directory)
					fromSources[source] = append(fromSources[source], line)
					denyCount++
				}
			}
		}
	}

	return denyCount
}

// == //

// GenerateProfileHead Function
func GenerateProfileHead(processWhiteList, fileWhiteList, networkWhiteList, capabilitiesWhiteList bool, profileBody string) string {
	// pre

	profileBody = profileBody + "  #include <abstractions/base>\n"
	profileBody = profileBody + "  umount,\n"

	if !(processWhiteList || fileWhiteList) {
		profileBody = profileBody + "  file,\n"
	}

	if !networkWhiteList {
		profileBody = profileBody + "  network,\n"
	}

	if !capabilitiesWhiteList {
		profileBody = profileBody + "  capability,\n"
	}

	return profileBody
}

// GenerateProfileFoot Function
func GenerateProfileFoot(profileBody string) string {
	// post

	profileBody = profileBody + "  deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,\n"
	profileBody = profileBody + "  deny @{PROC}/sysrq-trigger rwklx,\n"
	profileBody = profileBody + "  deny @{PROC}/mem rwklx,\n"
	profileBody = profileBody + "  deny @{PROC}/kmem rwklx,\n"
	profileBody = profileBody + "  deny @{PROC}/kcore rwklx,\n"
	profileBody = profileBody + "\n"
	profileBody = profileBody + "  deny mount,\n"
	profileBody = profileBody + "\n"
	profileBody = profileBody + "  deny /sys/[^f]*/** wklx,\n"
	profileBody = profileBody + "  deny /sys/f[^s]*/** wklx,\n"
	profileBody = profileBody + "  deny /sys/fs/[^c]*/** wklx,\n"
	profileBody = profileBody + "  deny /sys/fs/c[^g]*/** wklx,\n"
	profileBody = profileBody + "  deny /sys/fs/cg[^r]*/** wklx,\n"
	profileBody = profileBody + "  deny /sys/firmware/efi/efivars/** rwklx,\n"
	profileBody = profileBody + "  deny /sys/kernel/security/** rwklx,\n"

	return profileBody
}

// == //

// GenerateProfileBody Function
func GenerateProfileBody(oldContentsPreMid, oldConetntsMidPost []string, securityPolicies []tp.SecurityPolicy) (int, int, int, string) {
	// global profile body

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

	// head

	profileBody := "  ## == PRE START == ##\n"

	profileBody = GenerateProfileHead(processWhiteList, fileWhiteList, networkWhiteList, capabilitiesWhiteList, profileBody)

	profileBody = profileBody + "  ## == PRE END == ##\n"

	// between head and body

	for _, preMid := range oldContentsPreMid {
		profileBody = profileBody + preMid
	}

	// profile body

	profileBody = profileBody + "  ## == POLICY START == ##\n"

	for _, line := range allowLines {
		profileBody = profileBody + line
	}

	for _, line := range auditLines {
		profileBody = profileBody + line
	}

	for _, line := range denyLines {
		profileBody = profileBody + line
	}

	if processWhiteList || fileWhiteList {
		profileBody = profileBody + "  /lib/x86_64-linux-gnu/{*,**} r,\n"
	}

	// profile body with fromSource

	fromSources := map[string][]string{}

	nAllowCount := 0
	nAuditCount := 0
	nDenyCount := 0

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Allow" || secPolicy.Spec.Action == "AllowWithAudit" {
			// process
			nAllowCount = allowedProcessesFromSource(secPolicy, fromSources, nAllowCount)

			// file
			nAllowCount = allowedFilesFromSource(secPolicy, fromSources, nAllowCount)
		}
	}

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Audit" {
			// process
			nAuditCount = auditedProcessesFromSource(secPolicy, fromSources, nAuditCount)

			// file
			nAuditCount = auditedFilesFromSource(secPolicy, fromSources, nAuditCount)
		}
	}

	for _, secPolicy := range securityPolicies {
		if secPolicy.Spec.Action == "Block" {
			// process
			nDenyCount = blockedProcessesFromSource(secPolicy, fromSources, nDenyCount)

			// file
			nDenyCount = blockedFilesFromSource(secPolicy, fromSources, nDenyCount)
		}
	}

	bodyFromSource := ""

	for source, lines := range fromSources {
		bodyFromSource = bodyFromSource + fmt.Sprintf("  %s cx,\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("  profile %s {\n", source)

		head := fmt.Sprintf(" (%s) == ##", source)
		subProfileBody := strings.Replace(profileBody, " == ##", head, -1)
		bodyFromSource = bodyFromSource + subProfileBody

		if processWhiteList || fileWhiteList {
			bodyFromSource = bodyFromSource + fmt.Sprintf("  %s r,\n", source)
		}

		for _, line := range lines {
			bodyFromSource = bodyFromSource + line
		}

		bodyFromSource = bodyFromSource + fmt.Sprintf("  ## == POLICY END (%s) == ##\n\n", source)
		bodyFromSource = bodyFromSource + fmt.Sprintf("  ## == POST START (%s) == ##\n", source)

		bodyFromSource = GenerateProfileFoot(bodyFromSource)

		bodyFromSource = bodyFromSource + fmt.Sprintf("  ## == POST END (%s) == ##\n", source)
		bodyFromSource = bodyFromSource + "  }\n"
	}

	profileBody = profileBody + bodyFromSource

	allowCount = allowCount + nAllowCount
	auditCount = auditCount + nAuditCount
	denyCount = denyCount + nDenyCount

	profileBody = profileBody + "  ## == POLICY END == ##\n"

	// between body and foot

	for _, midPost := range oldConetntsMidPost {
		profileBody = profileBody + midPost
	}

	// foot

	profileBody = profileBody + "  ## == POST START == ##\n"

	profileBody = GenerateProfileFoot(profileBody)

	profileBody = profileBody + "  ## == POST END == ##\n"

	return allowCount, auditCount, denyCount, profileBody
}

// == //

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
		} else if pos == "POST" {
			//
		} else if pos == "FOOT" {
			oldContentsFoot = append(oldContentsFoot, line+"\n")
		}
	}

	file.Close()

	// generate a profile body

	allowCount, auditCount, denyCount, profileBody := GenerateProfileBody(oldContentsPreMid, oldConetntsMidPost, securityPolicies)

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
		return allowCount + auditCount + denyCount, newProfile, true
	}

	return 0, "", false
}
