// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

// AllowedProcessMatchPaths Function
func (se *SELinuxEnforcer) AllowedProcessMatchPaths(path tp.ProcessPathType, fromSources map[string][]tp.SELinuxRule) {
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

		rule := tp.SELinuxRule{SubjectLabel: "karmorA_exec_t", SubjectPath: source, ObjectLabel: "karmorA_allow_t", ObjectPath: path.Path}
		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// AllowedProcessMatchDirectories Function
func (se *SELinuxEnforcer) AllowedProcessMatchDirectories(dir tp.ProcessDirectoryType, fromSources map[string][]tp.SELinuxRule) {
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
			rule = tp.SELinuxRule{SubjectLabel: "karmorA_exec_t", SubjectPath: source, ObjectLabel: "karmorA_allow_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "karmorA_exec_t", SubjectPath: source, ObjectLabel: "karmorA_allow_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// AllowedFileMatchPaths Function
func (se *SELinuxEnforcer) AllowedFileMatchPaths(path tp.FilePathType, fromSources map[string][]tp.SELinuxRule) {
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
			rule = tp.SELinuxRule{SubjectLabel: "karmorA_exec_t", SubjectPath: source, ObjectLabel: "karmorA_read_t", ObjectPath: path.Path}
		} else { // !path.ReadOnly
			rule = tp.SELinuxRule{SubjectLabel: "karmorA_exec_t", SubjectPath: source, ObjectLabel: "karmorA_file_t", ObjectPath: path.Path}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// AllowedFileMatchDirectories Function
func (se *SELinuxEnforcer) AllowedFileMatchDirectories(dir tp.FileDirectoryType, fromSources map[string][]tp.SELinuxRule) {
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
			rule = tp.SELinuxRule{SubjectLabel: "karmorA_exec_t", SubjectPath: source, ObjectLabel: "karmorA_read_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else if dir.ReadOnly && !dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "karmorA_exec_t", SubjectPath: source, ObjectLabel: "karmorA_read_t", ObjectPath: dir.Directory, Directory: true}
		} else if !dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "karmorA_exec_t", SubjectPath: source, ObjectLabel: "karmorA_file_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.ReadOnly && !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "karmorA_exec_t", SubjectPath: source, ObjectLabel: "karmorA_file_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

//

// BlockedProcessMatchPaths Function
func (se *SELinuxEnforcer) BlockedProcessMatchPaths(path tp.ProcessPathType, processBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		rule := tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "karmorG_block_t", ObjectPath: path.Path}
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

		rule := tp.SELinuxRule{SubjectLabel: "karmorB_exec_t", SubjectPath: source, ObjectLabel: "karmorB_block_t", ObjectPath: path.Path}
		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// BlockedProcessMatchDirectories Function
func (se *SELinuxEnforcer) BlockedProcessMatchDirectories(dir tp.ProcessDirectoryType, processBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		rule := tp.SELinuxRule{}

		if dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "karmorG_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "karmorG_block_t", ObjectPath: dir.Directory, Directory: true}
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
			rule = tp.SELinuxRule{SubjectLabel: "karmorB_exec_t", SubjectPath: source, ObjectLabel: "karmorB_block_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "karmorB_exec_t", SubjectPath: source, ObjectLabel: "karmorB_block_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// BlockedFileMatchPaths Function
func (se *SELinuxEnforcer) BlockedFileMatchPaths(path tp.FilePathType, fileBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(path.FromSource) == 0 {
		rule := tp.SELinuxRule{}

		if path.ReadOnly {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "karmorG_nowrite_t", ObjectPath: path.Path}
		} else { // !path.ReadOnly
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "karmorG_none_t", ObjectPath: path.Path}
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
			rule = tp.SELinuxRule{SubjectLabel: "karmorB_exec_t", SubjectPath: source, ObjectLabel: "karmorB_nowrite_t", ObjectPath: path.Path}
		} else { // !path.ReadOnly
			rule = tp.SELinuxRule{SubjectLabel: "karmorB_exec_t", SubjectPath: source, ObjectLabel: "karmorB_none_t", ObjectPath: path.Path}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// BlockedFileMatchDirectories Function
func (se *SELinuxEnforcer) BlockedFileMatchDirectories(dir tp.FileDirectoryType, fileBlackList *[]tp.SELinuxRule, fromSources map[string][]tp.SELinuxRule) {
	if len(dir.FromSource) == 0 {
		rule := tp.SELinuxRule{}

		if dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "karmorG_nowrite_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else if dir.ReadOnly && !dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "karmorG_nowrite_t", ObjectPath: dir.Directory, Directory: true}
		} else if !dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "karmorG_none_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.ReadOnly && !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "-", SubjectPath: "-", ObjectLabel: "karmorG_none_t", ObjectPath: dir.Directory, Directory: true}
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
			rule = tp.SELinuxRule{SubjectLabel: "karmorB_exec_t", SubjectPath: source, ObjectLabel: "karmorB_nowrite_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else if dir.ReadOnly && !dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "karmorB_exec_t", SubjectPath: source, ObjectLabel: "karmorB_nowrite_t", ObjectPath: dir.Directory, Directory: true}
		} else if !dir.ReadOnly && dir.Recursive {
			rule = tp.SELinuxRule{SubjectLabel: "karmorB_exec_t", SubjectPath: source, ObjectLabel: "karmorB_none_t", ObjectPath: dir.Directory, Directory: true, Recursive: true}
		} else { // !dir.ReadOnly && !dir.Recursive
			rule = tp.SELinuxRule{SubjectLabel: "karmorB_exec_t", SubjectPath: source, ObjectLabel: "karmorB_none_t", ObjectPath: dir.Directory, Directory: true}
		}

		if !kl.ContainsElement(fromSources[source], rule) {
			fromSources[source] = append(fromSources[source], rule)
		}
	}
}

// == //

// GenerateSELinuxProfile Function
func (se *SELinuxEnforcer) GenerateSELinuxProfile(seLinuxProfile string, securityPolicies []tp.SecurityPolicy) (int, string, bool) {
	count := 0

	processBlackList := []tp.SELinuxRule{}
	fileBlackList := []tp.SELinuxRule{}

	whiteListfromSources := map[string][]tp.SELinuxRule{}
	blackListfromSources := map[string][]tp.SELinuxRule{}

	// preparation

	for _, secPolicy := range securityPolicies {
		if len(secPolicy.Spec.Process.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.Process.MatchPaths {
				if path.Action == "Allow" {
					se.AllowedProcessMatchPaths(path, whiteListfromSources)
				} else if path.Action == "Audit" {
					//
				} else if path.Action == "Block" {
					se.BlockedProcessMatchPaths(path, &processBlackList, blackListfromSources)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" {
					se.AllowedProcessMatchDirectories(dir, whiteListfromSources)
				} else if dir.Action == "Audit" {
					//
				} else if dir.Action == "Block" {
					se.BlockedProcessMatchDirectories(dir, &processBlackList, blackListfromSources)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" {
					se.AllowedFileMatchPaths(path, whiteListfromSources)
				} else if path.Action == "Audit" {
					//
				} else if path.Action == "Block" {
					se.BlockedFileMatchPaths(path, &fileBlackList, blackListfromSources)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" {
					se.AllowedFileMatchDirectories(dir, whiteListfromSources)
				} else if dir.Action == "Audit" {
					//
				} else if dir.Action == "Block" {
					se.BlockedFileMatchDirectories(dir, &fileBlackList, blackListfromSources)
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
		// make a string
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%t\t%t\t%t\n",
			rule.SubjectLabel, rule.SubjectPath, rule.ObjectLabel, rule.ObjectPath, rule.Permissive, rule.Directory, rule.Recursive)

		// add the string
		newProfile = newProfile + line
	}

	for _, rule := range globalRules {
		// make a string
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%t\t%t\t%t\n",
			rule.SubjectLabel, rule.SubjectPath, rule.ObjectLabel, rule.ObjectPath, rule.Permissive, rule.Directory, rule.Recursive)

		// add the string
		newProfile = newProfile + line
	}

	// check if the old profile exists

	if _, err := os.Stat(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + seLinuxProfile)); os.IsNotExist(err) {
		return 0, err.Error(), false
	}

	// get the old profile

	profile, err := ioutil.ReadFile(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + seLinuxProfile))
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
