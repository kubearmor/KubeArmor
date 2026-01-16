// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

package enforcer

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	sprig "github.com/Masterminds/sprig/v3"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"k8s.io/utils/strings/slices"
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
func (ae *AppArmorEnforcer) SetProcessMatchPaths(path tp.ProcessPathType, prof *Profile, deny bool, head bool) {
	if !deny {
		prof.File = head
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.Allow = !deny
	rule.OwnerOnly = path.OwnerOnly

	if len(path.FromSource) == 0 {
		if len(path.ExecName) > 0 {
			addRuletoMap(rule, "/**/"+path.ExecName, prof.ProcessPaths)
			return
		}
		addRuletoMap(rule, path.Path, prof.ProcessPaths)
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
		if !deny {
			if val, ok := prof.FromSource[source]; ok {
				val.File = head
				prof.FromSource[source] = val
			}
		}
		if len(path.ExecName) > 0 {
			addRuletoMap(rule, "/**/"+path.ExecName, prof.FromSource[source].ProcessPaths)
			continue
		}
		addRuletoMap(rule, path.Path, prof.FromSource[source].ProcessPaths)
	}
}

// SetProcessMatchDirectories Function
func (ae *AppArmorEnforcer) SetProcessMatchDirectories(dir tp.ProcessDirectoryType, prof *Profile, deny bool, head bool) {
	if !deny {
		prof.File = head
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.Allow = !deny
	rule.Dir = true
	rule.Recursive = dir.Recursive
	rule.OwnerOnly = dir.OwnerOnly

	if len(dir.FromSource) == 0 {
		addRuletoMap(rule, dir.Directory, prof.ProcessPaths)

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
		if !deny {
			if val, ok := prof.FromSource[source]; ok {
				val.File = head
				prof.FromSource[source] = val
			}
		}
		addRuletoMap(rule, dir.Directory, prof.FromSource[source].ProcessPaths)
	}
}

// SetProcessMatchPatterns Function
func (ae *AppArmorEnforcer) SetProcessMatchPatterns(pat tp.ProcessPatternType, prof *Profile, deny bool, head bool) {
	if !deny {
		prof.File = head
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.Allow = !deny
	rule.OwnerOnly = pat.OwnerOnly

	if _, ok := prof.ProcessPaths[pat.Pattern]; !ok {
		prof.ProcessPaths[pat.Pattern] = rule
	}
}

// SetFileMatchPaths Function
func (ae *AppArmorEnforcer) SetFileMatchPaths(path tp.FilePathType, prof *Profile, deny bool, head bool) {
	if !deny {
		prof.File = head
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.Allow = !deny
	rule.OwnerOnly = path.OwnerOnly
	rule.ReadOnly = path.ReadOnly

	if len(path.FromSource) == 0 {
		addRuletoMap(rule, path.Path, prof.FilePaths)

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
		if !deny {
			if val, ok := prof.FromSource[source]; ok {
				val.File = head
				prof.FromSource[source] = val
			}
		}
		addRuletoMap(rule, path.Path, prof.FromSource[source].FilePaths)
	}
}

// SetFileMatchDirectories Function
func (ae *AppArmorEnforcer) SetFileMatchDirectories(dir tp.FileDirectoryType, prof *Profile, deny bool, head bool) {
	if !deny {
		prof.File = head
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.Allow = !deny
	rule.OwnerOnly = dir.OwnerOnly
	rule.ReadOnly = dir.ReadOnly
	rule.Dir = true
	rule.Recursive = dir.Recursive

	if len(dir.FromSource) == 0 {
		addRuletoMap(rule, dir.Directory, prof.FilePaths)

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
		if !deny {
			if val, ok := prof.FromSource[source]; ok {
				val.File = head
				prof.FromSource[source] = val
			}
		}
		addRuletoMap(rule, dir.Directory, prof.FromSource[source].FilePaths)
	}
}

// SetFileMatchPatterns Function
func (ae *AppArmorEnforcer) SetFileMatchPatterns(pat tp.FilePatternType, prof *Profile, deny bool, head bool) {
	if !deny {
		prof.File = head
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.Allow = !deny
	rule.OwnerOnly = pat.OwnerOnly
	rule.ReadOnly = pat.ReadOnly

	if _, ok := prof.FilePaths[pat.Pattern]; !ok {
		prof.FilePaths[pat.Pattern] = rule
	}
}

// SetNetworkMatchProtocols Function
func (ae *AppArmorEnforcer) SetNetworkMatchProtocols(proto tp.NetworkProtocolType, prof *Profile, deny bool, head bool) {
	//forcing the protocol to lowercase
	proto.Protocol = strings.ToLower(proto.Protocol)

	// handle icmpv6 protocol same as icmp
	if proto.Protocol == "icmpv6" {
		proto.Protocol = "icmp"
	}

	if !deny {
		prof.Network = head
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.Allow = !deny
	if len(proto.FromSource) == 0 {
		addRuletoMap(rule, proto.Protocol, prof.NetworkRules)
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
		if !deny {
			if val, ok := prof.FromSource[source]; ok {
				val.Network = head
				prof.FromSource[source] = val
			}
		}
		addRuletoMap(rule, proto.Protocol, prof.FromSource[source].NetworkRules)
	}
}

// SetCapabilitiesMatchCapabilities Function
func (ae *AppArmorEnforcer) SetCapabilitiesMatchCapabilities(cap tp.CapabilitiesCapabilityType, prof *Profile, deny bool, head bool) {
	if !deny {
		prof.Capabilities = head
	}
	rule := RuleConfig{}
	rule.Deny = deny
	rule.Allow = !deny
	if len(cap.FromSource) == 0 {
		addRuletoMap(rule, cap.Capability, prof.CapabilitiesRules)
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
		if !deny {
			if val, ok := prof.FromSource[source]; ok {
				val.Capabilities = head
				prof.FromSource[source] = val
			}
		}
		addRuletoMap(rule, cap.Capability, prof.FromSource[source].CapabilitiesRules)
	}
}

// == //

// GenerateProfileBody Function
func (ae *AppArmorEnforcer) GenerateProfileBody(securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture, privileged bool) (int, Profile) {
	// preparation

	count := 0

	var profile Profile
	profile.Init()

	if privileged {
		profile.Privileged = true
	}

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
				if path.Action == "Allow" {
					ae.SetProcessMatchPaths(path, &profile, false, defaultPosture.FileAction != "block")
				} else if path.Action == "Block" {
					ae.SetProcessMatchPaths(path, &profile, true, true)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.Process.MatchDirectories {
				if dir.Action == "Allow" {
					ae.SetProcessMatchDirectories(dir, &profile, false, defaultPosture.FileAction != "block")
				} else if dir.Action == "Block" {
					ae.SetProcessMatchDirectories(dir, &profile, true, true)
				}
			}
		}
		if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.Process.MatchPatterns {
				if pat.Action == "Allow" {
					ae.SetProcessMatchPatterns(pat, &profile, false, defaultPosture.FileAction != "block")
				} else if pat.Action == "Block" {
					ae.SetProcessMatchPatterns(pat, &profile, true, true)
				}
			}
		}

		if len(secPolicy.Spec.File.MatchPaths) > 0 {
			for _, path := range secPolicy.Spec.File.MatchPaths {
				if path.Action == "Allow" {
					ae.SetFileMatchPaths(path, &profile, false, defaultPosture.FileAction != "block")
				} else if path.Action == "Block" {
					ae.SetFileMatchPaths(path, &profile, true, true)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchDirectories) > 0 {
			for _, dir := range secPolicy.Spec.File.MatchDirectories {
				if dir.Action == "Allow" {
					ae.SetFileMatchDirectories(dir, &profile, false, defaultPosture.FileAction != "block")
				} else if dir.Action == "Block" {
					ae.SetFileMatchDirectories(dir, &profile, true, true)
				}
			}
		}
		if len(secPolicy.Spec.File.MatchPatterns) > 0 {
			for _, pat := range secPolicy.Spec.File.MatchPatterns {
				if pat.Action == "Allow" {
					ae.SetFileMatchPatterns(pat, &profile, false, defaultPosture.FileAction != "block")
				} else if pat.Action == "Block" {
					ae.SetFileMatchPatterns(pat, &profile, true, true)
				}
			}
		}

		if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
			for _, proto := range secPolicy.Spec.Network.MatchProtocols {
				if proto.Action == "Allow" {
					ae.SetNetworkMatchProtocols(proto, &profile, false, defaultPosture.NetworkAction != "block")
				} else if proto.Action == "Block" {
					ae.SetNetworkMatchProtocols(proto, &profile, true, true)
				}
			}
		}

		if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
			for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
				if cap.Action == "Allow" {
					ae.SetCapabilitiesMatchCapabilities(cap, &profile, false, defaultPosture.CapabilitiesAction != "block")
				} else if cap.Action == "Block" {
					ae.SetCapabilitiesMatchCapabilities(cap, &profile, true, true)
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
		err := kl.Clone(val, &newval)
		if err != nil {
			ae.Logger.Errf("Error while copying global rules to local profile for %s: %s", source, err.Error())
			continue
		}
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
func (ae *AppArmorEnforcer) GenerateAppArmorProfile(appArmorProfile string, securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture, privileged bool) (int, string, bool) {
	// check apparmor profile
	var oldProfile string
	if strings.Contains(appArmorProfile, "kubearmor.host") {
		if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + "kubearmor.host")); os.IsNotExist(err) {
			return 0, err.Error(), false
		}

		// get the old profile
		profile, err := os.ReadFile(filepath.Clean("/etc/apparmor.d/" + "kubearmor.host"))
		if err != nil {
			return 0, err.Error(), false
		}
		oldProfile = string(profile)
	} else {
		// this path is expected to have a single componenet "apparmor-profile"
		// and this is to ensure that the filename has no path separators or parent directory references
		if strings.Contains(appArmorProfile, "/") || strings.Contains(appArmorProfile, "\\") || strings.Contains(appArmorProfile, "..") {
			ae.Logger.Warnf("Invalid appArmor profile name (%s)", appArmorProfile)
			return 0, "Invalid apparmor profile name: " + appArmorProfile, false
		}

		if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + appArmorProfile)); os.IsNotExist(err) {
			return 0, err.Error(), false
		}

		// get the old profile

		profile, err := os.ReadFile(filepath.Clean("/etc/apparmor.d/" + appArmorProfile))
		if err != nil {
			return 0, err.Error(), false
		}
		oldProfile = string(profile)
	}

	// generate a profile body

	count, newProfile := ae.GenerateProfileBody(securityPolicies, defaultPosture, privileged)

	newProfile.Name = appArmorProfile

	// https://helm.sh/docs/howto/charts_tips_and_tricks/
	// Extend go template with sprig functions

	allFuncs := sprig.GenericFuncMap()
	delete(allFuncs, "env")
	delete(allFuncs, "expandenv")

	// Create a new template and parse the letter into it.
	t, err := template.New("apparmor").Funcs(allFuncs).Parse(BaseTemplate)
	if err != nil {
		return 0, err.Error(), false
	}

	var np bytes.Buffer
	if err := t.Execute(&np, newProfile); err != nil {
		return 0, err.Error(), false
	}

	// check the new profile with the old profile

	if np.String() != oldProfile {
		// check if we need to off load profile
		oldProfilesNames := ae.rgx.FindAllString(oldProfile, -1)
		newProfilesNames := ae.rgx.FindAllString(np.String(), -1)
		profileToDelete := []string{}
		for _, oldProf := range oldProfilesNames {
			if !slices.Contains(newProfilesNames, oldProf) {
				profileToDelete = append(profileToDelete, oldProf)
			}
		}
		if len(profileToDelete) != 0 {
			file, err := os.CreateTemp("/tmp", "apparmor-")
			if err != nil {
				ae.Logger.Warnf("Unable to create tmp file, err=%s", err.Error())
			} else {
				defer os.Remove(file.Name())
				writer := bufio.NewWriter(file)
				for _, prof := range profileToDelete {
					_, err = writer.WriteString(prof + "} \n")
					if err != nil {
						ae.Logger.Warnf("Unable to write deleted profile %s to tmp file, err=%s", prof+"}", err.Error())
					}
				}
				err = writer.Flush()
				if err != nil {
					ae.Logger.Warnf("Cannot flush tmp file writer buffer, err=%s", err.Error())
				}
				if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-R", file.Name()}); err != nil {
					ae.Logger.Warnf("Unable to unload %d unused apparmor profiles, err=%s", len(profileToDelete), err.Error())
				}
			}
		}

		return count, np.String(), true
	}

	return 0, "", false
}

func addRuletoMap(rule RuleConfig, entity string, m map[string]RuleConfig) {
	if val, ok := m[entity]; ok {
		if val.Deny != rule.Deny {
			rule.Deny = true
			rule.Allow = true
		} else {
			return
		}
	}
	m[entity] = rule
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
