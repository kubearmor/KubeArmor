// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

package enforcer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

// AllowedHostProcessMatchPaths Function
func (se *SELinuxEnforcer) AllowedHostProcessMatchPaths(path tp.ProcessPathType, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		return
	}

	for _, src := range path.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []tp.SELinuxRule{}
		}

		rule := tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "allow_t", ObjectPath: path.Path}
		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// AllowedHostProcessMatchDirectories Function
func (se *SELinuxEnforcer) AllowedHostProcessMatchDirectories(dir tp.ProcessDirectoryType, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		return
	}

	for _, src := range dir.FromSource {
		rule := tp.SELinuxRule{}

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []tp.SELinuxRule{}
		}

		if dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "allow_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "allow_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// AllowedHostFileMatchPaths Function
func (se *SELinuxEnforcer) AllowedHostFileMatchPaths(path tp.FilePathType, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		return
	}

	for _, src := range path.FromSource {
		rule := tp.SELinuxRule{}

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []tp.SELinuxRule{}
		}

		if path.ReadOnly {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "read_t", ObjectPath: path.Path}
		} else { // !path.ReadOnly
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "file_t", ObjectPath: path.Path}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// AllowedHostFileMatchDirectories Function
func (se *SELinuxEnforcer) AllowedHostFileMatchDirectories(dir tp.FileDirectoryType, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		return
	}

	for _, src := range dir.FromSource {
		rule := tp.SELinuxRule{}

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []tp.SELinuxRule{}
		}

		if dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else if dir.ReadOnly && !dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "read_t", ObjectPath: dir.Directory, Directory: true}
		} else if !dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.ReadOnly && !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "file_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// AllowedHostNetworkMatchProtocols Function
func (se *SELinuxEnforcer) AllowedHostNetworkMatchProtocols(proto tp.NetworkProtocolType, networkFromSources map[string]string) {
	if len(proto.FromSource) == 0 {
		return
	}

	for _, src := range proto.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		tcp := "n"
		udp := "n"
		icmp := "n"
		raw := "n"

		for proto := range strings.SplitSeq(proto.Protocol, ",") {
			if proto == "tcp" {
				tcp = "t"
			} else if proto == "udp" {
				udp = "u"
			} else if proto == "icmp" {
				icmp = "i"
			} else if proto == "raw" {
				raw = "r"
			}
		}

		networkFromSources[src.Path] = tcp + udp + icmp + raw
	}
}

//

// BlockedHostProcessMatchPaths Function
func (se *SELinuxEnforcer) BlockedHostProcessMatchPaths(path tp.ProcessPathType, processBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		rule := tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "block_t", ObjectPath: path.Path}
		if !kl.ContainsElement(*processBlackList, rule) {
			*processBlackList = append(*processBlackList, rule)
		}
		return
	}

	for _, src := range path.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []tp.SELinuxRule{}
		}

		rule := tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "block_t", ObjectPath: path.Path}
		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// BlockedHostProcessMatchDirectories Function
func (se *SELinuxEnforcer) BlockedHostProcessMatchDirectories(dir tp.ProcessDirectoryType, processBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		rule := tp.SELinuxRule{}

		if dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "block_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(*processBlackList, rule) {
			*processBlackList = append(*processBlackList, rule)
		}

		return
	}

	for _, src := range dir.FromSource {
		rule := tp.SELinuxRule{}

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []tp.SELinuxRule{}
		}

		if dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "block_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// BlockedHostFileMatchPaths Function
func (se *SELinuxEnforcer) BlockedHostFileMatchPaths(path tp.FilePathType, fileBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		rule := tp.SELinuxRule{}

		if path.ReadOnly {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "read_t", ObjectPath: path.Path}
		} else { // !path.ReadOnly
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "none_t", ObjectPath: path.Path}
		}

		if !kl.ContainsElement(*fileBlackList, rule) {
			*fileBlackList = append(*fileBlackList, rule)
		}

		return
	}

	for _, src := range path.FromSource {
		rule := tp.SELinuxRule{}

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []tp.SELinuxRule{}
		}

		if path.ReadOnly {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "read_t", ObjectPath: path.Path}
		} else { // !path.ReadOnly
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "none_t", ObjectPath: path.Path}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// BlockedHostFileMatchDirectories Function
func (se *SELinuxEnforcer) BlockedHostFileMatchDirectories(dir tp.FileDirectoryType, fileBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		rule := tp.SELinuxRule{}

		if dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else if dir.ReadOnly && !dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "read_t", ObjectPath: dir.Directory, Directory: true}
		} else if !dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "none_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.ReadOnly && !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "none_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(*fileBlackList, rule) {
			*fileBlackList = append(*fileBlackList, rule)
		}

		return
	}

	for _, src := range dir.FromSource {
		rule := tp.SELinuxRule{}

		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := fromSources[source]; !ok {
			fromSources[source] = []tp.SELinuxRule{}
		}

		if dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else if dir.ReadOnly && !dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "read_t", ObjectPath: dir.Directory, Directory: true}
		} else if !dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "none_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.ReadOnly && !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "exec_t", SubjectPath: source, ObjectLabel: "none_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// BlockedHostNetworkMatchProtocols Function
func (se *SELinuxEnforcer) BlockedHostNetworkMatchProtocols(proto tp.NetworkProtocolType, networkFromSources map[string]string) {
	if len(proto.FromSource) == 0 {
		return
	}

	for _, src := range proto.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		tcp := "t"
		udp := "u"
		icmp := "r"
		raw := "i"

		for proto := range strings.SplitSeq(proto.Protocol, ",") {
			if proto == "tcp" {
				tcp = "n"
			} else if proto == "udp" {
				udp = "n"
			} else if proto == "icmp" {
				icmp = "n"
			} else if proto == "raw" {
				raw = "n"
			}
		}

		networkFromSources[src.Path] = tcp + udp + icmp + raw
	}
}

// == //

// GenerateSELinuxHostProfile Function
func (se *SELinuxEnforcer) GenerateSELinuxHostProfile(securityPolicies []tp.HostSecurityPolicy, defaultPosture tp.DefaultPosture) (int, string, bool) {
	count := 0

	processBlackList := []tp.SELinuxRule{}
	fileBlackList := []tp.SELinuxRule{}

	whiteListfromSources := map[string][]tp.SELinuxRule{}
	blackListfromSources := map[string][]tp.SELinuxRule{}

	networkFromSources := map[string]string{}

	// preparation

	for _, secPolicy := range securityPolicies {
		if len(secPolicy.Spec.Process.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.Process.MatchPaths {
				if path.Action == "Allow" {
					se.AllowedHostProcessMatchPaths(path, whiteListfromSources)
				} else if path.Action == "Block" {
					se.BlockedHostProcessMatchPaths(path, &processBlackList, blackListfromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" {
					se.AllowedHostProcessMatchDirectories(dir, whiteListfromSources)
				} else if dir.Action == "Block" {
					se.BlockedHostProcessMatchDirectories(dir, &processBlackList, blackListfromSources)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" {
					se.AllowedHostFileMatchPaths(path, whiteListfromSources)
				} else if path.Action == "Block" {
					se.BlockedHostFileMatchPaths(path, &fileBlackList, blackListfromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" {
					se.AllowedHostFileMatchDirectories(dir, whiteListfromSources)
				} else if dir.Action == "Block" {
					se.BlockedHostFileMatchDirectories(dir, &fileBlackList, blackListfromSources)
				}
			}
		}

		if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
			for _, proto := range secPolicy.Spec.Network.MatchProtocols {
				if proto.Action == "Allow" {
					se.AllowedHostNetworkMatchProtocols(proto, networkFromSources)
				} else if proto.Action == "Block" {
					se.BlockedHostNetworkMatchProtocols(proto, networkFromSources)
				}
			}
		}
	}

	// generate new rules

	globalRules := []tp.SELinuxRule{}
	localRules := []tp.SELinuxRule{}

	// black list

	for _, rule := range processBlackList {
		if rule.SubjectLabel == "-" {
			if !se.ContainsElement(globalRules, rule) {
				globalRules = append(globalRules, rule)
				count = count + 1
			}
		} else {
			if !se.ContainsElement(localRules, rule) {
				localRules = append(localRules, rule)
				count = count + 1
			}
		}
	}

	for _, rule := range fileBlackList {
		if rule.SubjectLabel == "-" {
			if !se.ContainsElement(globalRules, rule) {
				globalRules = append(globalRules, rule)
				count = count + 1
			}
		} else {
			if !se.ContainsElement(localRules, rule) {
				localRules = append(localRules, rule)
				count = count + 1
			}
		}
	}

	for _, rules := range blackListfromSources {
		for _, rule := range rules {
			if rule.SubjectLabel == "-" {
				if !se.ContainsElement(globalRules, rule) {
					globalRules = append(globalRules, rule)
					count = count + 1
				}
			} else {
				if !se.ContainsElement(localRules, rule) {
					localRules = append(localRules, rule)
					count = count + 1
				}
			}
		}
	}

	// white list

	for _, rules := range whiteListfromSources {
		for _, rule := range rules {
			if rule.SubjectLabel == "-" {
				if !se.ContainsElement(globalRules, rule) {
					globalRules = append(globalRules, rule)
					count = count + 1
				}
			} else {
				if !se.ContainsElement(localRules, rule) {
					localRules = append(localRules, rule)
					count = count + 1
				}
			}
		}
	}

	// generate a new profile

	newProfile := ""

	for _, rule := range localRules {
		netFlags := "tuir"
		if _, ok := networkFromSources[rule.SubjectPath]; ok {
			netFlags = networkFromSources[rule.SubjectPath]
		}

		// make a string
		line := fmt.Sprintf("karmor_%s_%s_%s\t%s\tkarmor_%s_%s_%s\t%s\t%t\t%t\t%t\n",
			defaultPosture.FileAction, netFlags, rule.SubjectLabel, rule.SubjectPath,
			defaultPosture.FileAction, netFlags, rule.ObjectLabel, rule.ObjectPath,
			rule.Permissive, rule.Directory, rule.Recursive)

		// add the string
		newProfile = newProfile + line
	}

	for _, rule := range globalRules {
		// make a string
		line := fmt.Sprintf("%s\t%s\tkarmor_global_%s\t%s\t%t\t%t\t%t\n",
			rule.SubjectLabel, rule.SubjectPath, rule.ObjectLabel, rule.ObjectPath,
			rule.Permissive, rule.Directory, rule.Recursive)

		// add the string
		newProfile = newProfile + line
	}

	// check if the old profile exists

	if _, err := os.Stat(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile)); os.IsNotExist(err) {
		return 0, err.Error(), false
	}

	// get the old profile

	profile, err := os.ReadFile(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile))
	if err != nil {
		return 0, err.Error(), false
	}
	oldProfile := string(profile)

	// check if the new profile and the old one are the same

	if oldProfile != newProfile {
		return count, newProfile, true
	}

	return 0, "", false
}
