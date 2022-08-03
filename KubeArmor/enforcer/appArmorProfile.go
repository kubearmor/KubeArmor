// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// == //

// ResolvedProcessWhiteListConflicts Function
func (ae *AppArmorEnforcer) ResolvedProcessWhiteListConflicts(prof *Profile) {
	for source, val := range prof.FromSource {
		if _, ok := prof.ProcessPaths[source]; ok {
			val.Fusion = true
			prof.FromSource[source] = val
			delete(prof.ProcessPaths, source)
		}
	}
}

// SetProcessMatchPaths Function
func (ae *AppArmorEnforcer) SetProcessMatchPaths(path tp.ProcessPathType, prof *Profile, deny bool) {
	if deny == false {
		prof.File = false
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.OwnerOnly = path.OwnerOnly

	if len(path.FromSource) == 0 {
		if _, ok := prof.ProcessPaths[path.Path]; !ok {
			prof.ProcessPaths[path.Path] = rule
		}

		return
	}

	for _, src := range path.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := prof.FromSource[source]; !ok {
			var fromsource FromSourceConfig
			fromsource.ProfileHeader.Init()
			fromsource.Rules.Init()
			prof.FromSource[source] = fromsource
		}
		if deny == false {
			if val, ok := prof.FromSource[source]; ok {
				val.File = false
				prof.FromSource[source] = val
			}
		}
		if _, ok := prof.FromSource[source].ProcessPaths[path.Path]; !ok {
			prof.ProcessPaths[path.Path] = rule
		}
	}
}

// SetProcessMatchDirectories Function
func (ae *AppArmorEnforcer) SetProcessMatchDirectories(dir tp.ProcessDirectoryType, prof *Profile, deny bool) {
	if deny == false {
		prof.File = false
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.Dir = true
	rule.Recursive = dir.Recursive
	rule.OwnerOnly = dir.OwnerOnly

	if len(dir.FromSource) == 0 {
		if _, ok := prof.ProcessPaths[dir.Directory]; !ok {
			prof.ProcessPaths[dir.Directory] = rule
		}

		return
	}

	for _, src := range dir.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := prof.FromSource[source]; !ok {
			var fromsource FromSourceConfig
			fromsource.ProfileHeader.Init()
			fromsource.Rules.Init()
			prof.FromSource[source] = fromsource
		}
		if deny == false {
			if val, ok := prof.FromSource[source]; ok {
				val.File = false
				prof.FromSource[source] = val
			}
		}
		if _, ok := prof.FromSource[source].ProcessPaths[dir.Directory]; !ok {
			prof.FromSource[source].ProcessPaths[dir.Directory] = rule
		}
	}
}

// SetProcessMatchPatterns Function
func (ae *AppArmorEnforcer) SetProcessMatchPatterns(pat tp.ProcessPatternType, prof *Profile, deny bool) {
	if deny == false {
		prof.File = false
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.OwnerOnly = pat.OwnerOnly

	if _, ok := prof.ProcessPaths[pat.Pattern]; !ok {
		prof.ProcessPaths[pat.Pattern] = rule
	}
}

// SetFileMatchPaths Function
func (ae *AppArmorEnforcer) SetFileMatchPaths(path tp.FilePathType, prof *Profile, deny bool) {
	if deny == false {
		prof.File = false
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.OwnerOnly = path.OwnerOnly
	rule.ReadOnly = path.ReadOnly

	if len(path.FromSource) == 0 {
		if _, ok := prof.FilePaths[path.Path]; !ok {
			prof.FilePaths[path.Path] = rule
		}

		return
	}

	for _, src := range path.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := prof.FromSource[source]; !ok {
			var fromsource FromSourceConfig
			fromsource.ProfileHeader.Init()
			fromsource.Rules.Init()
			prof.FromSource[source] = fromsource
		}
		if deny == false {
			if val, ok := prof.FromSource[source]; ok {
				val.File = false
				prof.FromSource[source] = val
			}
		}
		if _, ok := prof.FromSource[source].FilePaths[path.Path]; !ok {
			prof.FromSource[source].FilePaths[path.Path] = rule
		}
	}
}

// SetFileMatchDirectories Function
func (ae *AppArmorEnforcer) SetFileMatchDirectories(dir tp.FileDirectoryType, prof *Profile, deny bool) {
	if deny == false {
		prof.File = false
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.OwnerOnly = dir.OwnerOnly
	rule.ReadOnly = dir.ReadOnly
	rule.Dir = true
	rule.Recursive = dir.Recursive

	if len(dir.FromSource) == 0 {
		if _, ok := prof.FilePaths[dir.Directory]; !ok {
			prof.FilePaths[dir.Directory] = rule
		}

		return
	}

	for _, src := range dir.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := prof.FromSource[source]; !ok {
			var fromsource FromSourceConfig
			fromsource.ProfileHeader.Init()
			fromsource.Rules.Init()
			prof.FromSource[source] = fromsource
		}
		if deny == false {
			if val, ok := prof.FromSource[source]; ok {
				val.File = false
				prof.FromSource[source] = val
			}
		}
		if _, ok := prof.FromSource[source].FilePaths[dir.Directory]; !ok {
			prof.FromSource[source].FilePaths[dir.Directory] = rule
		}
	}
}

// SetFileMatchPatterns Function
func (ae *AppArmorEnforcer) SetFileMatchPatterns(pat tp.FilePatternType, prof *Profile, deny bool) {
	if deny == false {
		prof.File = false
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.OwnerOnly = pat.OwnerOnly
	rule.ReadOnly = pat.ReadOnly

	if _, ok := prof.FilePaths[pat.Pattern]; !ok {
		prof.FilePaths[pat.Pattern] = rule
	}
}

// SetNetworkMatchProtocols Function
func (ae *AppArmorEnforcer) SetNetworkMatchProtocols(proto tp.NetworkProtocolType, prof *Profile, deny bool) {
	if deny == false {
		prof.Network = false
	}
	rule := RuleConfig{}
	rule.Deny = deny
	if len(proto.FromSource) == 0 {
		if _, ok := prof.NetworkRules[proto.Protocol]; !ok {
			prof.NetworkRules[proto.Protocol] = rule
		}
		return
	}

	for _, src := range proto.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := prof.FromSource[source]; !ok {
			var fromsource FromSourceConfig
			fromsource.ProfileHeader.Init()
			fromsource.Rules.Init()
			prof.FromSource[source] = fromsource
		}
		if deny == false {
			if val, ok := prof.FromSource[source]; ok {
				val.Network = false
				prof.FromSource[source] = val
			}
		}
		if _, ok := prof.FromSource[source].NetworkRules[proto.Protocol]; !ok {
			prof.FromSource[source].NetworkRules[proto.Protocol] = rule
		}
	}
}

// SetCapabilitiesMatchCapabilities Function
func (ae *AppArmorEnforcer) SetCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, prof *Profile, deny bool) {
	if deny == false {
		prof.Network = false
	}
	rule := RuleConfig{}
	rule.Deny = deny
	if len(cap.FromSource) == 0 {
		if _, ok := prof.CapabilitiesRules[cap.Capability]; !ok {
			prof.CapabilitiesRules[cap.Capability] = rule
		}
		return
	}

	for _, src := range cap.FromSource {
		if len(src.Path) == 0 {
			continue
		}

		source := src.Path
		if _, ok := prof.FromSource[source]; !ok {
			var fromsource FromSourceConfig
			fromsource.ProfileHeader.Init()
			fromsource.Rules.Init()
			prof.FromSource[source] = fromsource
		}
		if deny == false {
			if val, ok := prof.FromSource[source]; ok {
				val.Capabilities = false
				prof.FromSource[source] = val
			}
		}
		if _, ok := prof.FromSource[source].CapabilitiesRules[cap.Capability]; !ok {
			prof.FromSource[source].CapabilitiesRules[cap.Capability] = rule
		}
	}
}

// == //

// GenerateProfileBody Function
func (ae *AppArmorEnforcer) GenerateProfileBody(securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) (int, Profile) {
	// preparation

	count := 0

	var profile Profile
	profile.Init()

	for _, secPolicy := range securityPolicies {
		if len(secPolicy.Spec.AppArmor) > 0 {
			scanner := bufio.NewScanner(strings.NewReader(secPolicy.Spec.AppArmor))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				profile.NativeRules = append(profile.NativeRules, line)
			}
		}

		if len(secPolicy.Spec.Process.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.Process.MatchPaths {
				if path.Action == "Allow" && defaultPosture.FileAction == "block" {
					ae.SetProcessMatchPaths(path, &profile, false)
				} else if path.Action == "Block" {
					ae.SetProcessMatchPaths(path, &profile, true)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
					ae.SetProcessMatchDirectories(dir, &profile, false)
				} else if dir.Action == "Block" {
					ae.SetProcessMatchDirectories(dir, &profile, true)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.Process.MatchPatterns {
				if pat.Action == "Allow" && defaultPosture.FileAction == "block" {
					ae.SetProcessMatchPatterns(pat, &profile, false)
				} else if pat.Action == "Block" {
					ae.SetProcessMatchPatterns(pat, &profile, true)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" && defaultPosture.FileAction == "block" {
					ae.SetFileMatchPaths(path, &profile, false)
				} else if path.Action == "Block" {
					ae.SetFileMatchPaths(path, &profile, true)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
					ae.SetFileMatchDirectories(dir, &profile, false)
				} else if dir.Action == "Block" {
					ae.SetFileMatchDirectories(dir, &profile, true)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.File.MatchPatterns {
				if pat.Action == "Allow" && defaultPosture.FileAction == "block" {
					ae.SetFileMatchPatterns(pat, &profile, false)
				} else if pat.Action == "Block" {
					ae.SetFileMatchPatterns(pat, &profile, true)
				}
			}
		}

		if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
			for _, proto := range secPolicy.Spec.Network.MatchProtocols {
				if proto.Action == "Allow" && defaultPosture.NetworkAction == "block" {
					ae.SetNetworkMatchProtocols(proto, &profile, false)
				} else if proto.Action == "Block" {
					ae.SetNetworkMatchProtocols(proto, &profile, true)
				}
			}
		}

		if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
			for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
				if cap.Action == "Allow" && defaultPosture.CapabilitiesAction == "block" {
					ae.SetCapabilitiesMatchCapabilities(cap, &profile, false)
				} else if cap.Action == "Block" {
					ae.SetCapabilitiesMatchCapabilities(cap, &profile, true)
				}
			}
		}
	}

	// Count the number of global security rules
	count = len(profile.ProcessPaths) + len(profile.FilePaths) + len(profile.NetworkRules) + len(profile.CapabilitiesRules)

	// Resolve conflicts
	ae.ResolvedProcessWhiteListConflicts(&profile)

	/**
		To resolve conflicting rules between Global and FromSource based rules, we take the approach to prefer the superset path or if the entities match we consider the config of rule in subprofile

		Suppose we have the following Global rules
		/etc/passwd
		/run/secrets/**
		/hello.txt

		and the following rules inside a particular from source
		/etc/*
		/run/secrets/token
		/hello.txt

		We resolve the conflicts and finally add the following rules to the from source subprofile
		/run/secrets/**
	?	/run/secrets/token
		/hello.txt (local config)
		/etc/*
	**/

	for source, val := range profile.FromSource {
		var newval FromSourceConfig
		kl.Clone(val, &newval)
		for proc, config := range profile.ProcessPaths {
			add := checkIfGlobalRuleToBeAdded(proc, val.ProcessPaths)
			if add {
				newval.ProcessPaths[proc] = config
			}
		}
		for file, config := range profile.FilePaths {
			add := checkIfGlobalRuleToBeAdded(file, val.FilePaths)
			if add {
				newval.FilePaths[file] = config
			}
		}
		for net, config := range profile.NetworkRules {
			if _, ok := val.NetworkRules[net]; !ok {
				newval.NetworkRules[net] = config
			}
		}
		for cap, config := range profile.CapabilitiesRules {
			if _, ok := val.CapabilitiesRules[cap]; !ok {
				newval.CapabilitiesRules[cap] = config
			}
		}

		profile.FromSource[source] = newval
		count = count + len(profile.FromSource[source].ProcessPaths) + len(profile.FromSource[source].FilePaths) + len(profile.FromSource[source].NetworkRules) + len(profile.FromSource[source].CapabilitiesRules)
	}

	return count, profile
}

// == //

// GenerateAppArmorProfile Function
func (ae *AppArmorEnforcer) GenerateAppArmorProfile(appArmorProfile string, securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) (int, string, bool) {
	// check apparmor profile

	if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + appArmorProfile)); os.IsNotExist(err) {
		return 0, err.Error(), false
	}

	// get the old profile

	profile, err := os.ReadFile(filepath.Clean("/etc/apparmor.d/" + appArmorProfile))
	if err != nil {
		return 0, err.Error(), false
	}
	oldProfile := string(profile)

	// generate a profile body

	count, newProfile := ae.GenerateProfileBody(securityPolicies, defaultPosture)

	newProfile.Name = appArmorProfile

	// Create a new template and parse the letter into it.
	t, err := template.New("apparmor").Parse(BaseTemplate)
	if err != nil {
		return 0, err.Error(), false
	}

	var np bytes.Buffer
	if err := t.Execute(&np, newProfile); err != nil {
		return 0, err.Error(), false
	}

	// check the new profile with the old profile

	if np.String() != oldProfile {
		return count, np.String(), true
	}

	return 0, "", false
}

func checkIfGlobalRuleToBeAdded(p string, val map[string]RuleConfig) bool {
	if _, ok := val[p]; !ok {
		paths := strings.Split(p, "/")
		add := true
		for i := 1; i < len(paths); i++ {
			var pdir = strings.Join(paths[0:i], "/") + "/"
			if conf, ok := val[pdir]; ok {
				if conf.Dir {
					if len(paths)-i > 1 {
						if !conf.Recursive {
							continue
						}
					}
					add = false
					break
				}
			}
		}
		return add
	}
	return false
}
