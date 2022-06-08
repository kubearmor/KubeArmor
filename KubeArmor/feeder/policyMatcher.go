// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package feeder

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ======================= //
// == Security Policies == //
// ======================= //

// getProtocolFromName Function
func getProtocolFromName(proto string) string {
	switch strings.ToLower(proto) {
	case "tcp":
		return "protocol=TCP"
	case "udp":
		return "protocol=UDP"
	case "icmp":
		return "protocol=ICMP"
	case "raw":
		return "type=SOCK_RAW"
	default:
		return "unknown"
	}
}

func getFileProcessUID(path string) string {
	info, err := os.Stat(path)
	if err == nil {
		stat := info.Sys().(*syscall.Stat_t)
		uid := stat.Uid

		return strconv.Itoa(int(uid))
	}

	return ""
}

// getOperationAndCapabilityFromName Function
func getOperationAndCapabilityFromName(capName string) (op, cap string) {
	switch strings.ToLower(capName) {
	case "net_raw":
		op = "Network"
		cap = "SOCK_RAW"
	default:
		return "", "unknown"
	}

	return op, cap
}

// newMatchPolicy Function
func (fd *Feeder) newMatchPolicy(policyEnabled int, policyName, src string, mp interface{}) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Source:     src,
	}

	if ppt, ok := mp.(tp.ProcessPathType); ok {
		match.Severity = strconv.Itoa(ppt.Severity)
		match.Tags = ppt.Tags
		match.Message = ppt.Message

		match.Operation = "Process"
		match.Resource = ppt.Path
		match.ResourceType = "Path"

		match.OwnerOnly = ppt.OwnerOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Allow" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Block" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else {
			match.Action = ppt.Action
		}
	} else if pdt, ok := mp.(tp.ProcessDirectoryType); ok {
		match.Severity = strconv.Itoa(pdt.Severity)
		match.Tags = pdt.Tags
		match.Message = pdt.Message

		match.Operation = "Process"
		match.Resource = pdt.Directory
		match.ResourceType = "Directory"

		match.OwnerOnly = pdt.OwnerOnly
		match.Recursive = pdt.Recursive

		if policyEnabled == tp.KubeArmorPolicyAudited && pdt.Action == "Allow" {
			match.Action = "Audit (" + pdt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && pdt.Action == "Block" {
			match.Action = "Audit (" + pdt.Action + ")"
		} else {
			match.Action = pdt.Action
		}
	} else if ppt, ok := mp.(tp.ProcessPatternType); ok {
		match.Severity = strconv.Itoa(ppt.Severity)
		match.Tags = ppt.Tags
		match.Message = ppt.Message

		match.Operation = "Process"
		match.Resource = ppt.Pattern
		match.ResourceType = "" // to be defined based on the pattern matching syntax

		match.OwnerOnly = ppt.OwnerOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Allow" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Block" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else {
			match.Action = ppt.Action
		}
	} else if fpt, ok := mp.(tp.FilePathType); ok {
		match.Severity = strconv.Itoa(fpt.Severity)
		match.Tags = fpt.Tags
		match.Message = fpt.Message

		match.Operation = "File"
		match.Resource = fpt.Path
		match.ResourceType = "Path"

		match.OwnerOnly = fpt.OwnerOnly
		match.ReadOnly = fpt.ReadOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Allow" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Block" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else {
			match.Action = fpt.Action
		}
	} else if fdt, ok := mp.(tp.FileDirectoryType); ok {
		match.Severity = strconv.Itoa(fdt.Severity)
		match.Tags = fdt.Tags
		match.Message = fdt.Message

		match.Operation = "File"
		match.Resource = fdt.Directory
		match.ResourceType = "Directory"

		match.OwnerOnly = fdt.OwnerOnly
		match.ReadOnly = fdt.ReadOnly
		match.Recursive = fdt.Recursive

		if policyEnabled == tp.KubeArmorPolicyAudited && fdt.Action == "Allow" {
			match.Action = "Audit (" + fdt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && fdt.Action == "Block" {
			match.Action = "Audit (" + fdt.Action + ")"
		} else {
			match.Action = fdt.Action
		}
	} else if fpt, ok := mp.(tp.FilePatternType); ok {
		match.Severity = strconv.Itoa(fpt.Severity)
		match.Tags = fpt.Tags
		match.Message = fpt.Message
		match.Operation = "File"
		match.Resource = fpt.Pattern
		match.ResourceType = "" // to be defined based on the pattern matching syntax

		match.OwnerOnly = fpt.OwnerOnly
		match.ReadOnly = fpt.ReadOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Allow" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Block" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else {
			match.Action = fpt.Action
		}
	} else if npt, ok := mp.(tp.NetworkProtocolType); ok {
		match.Severity = strconv.Itoa(npt.Severity)
		match.Tags = npt.Tags
		match.Message = npt.Message

		match.Operation = "Network"
		match.Resource = getProtocolFromName(npt.Protocol)
		match.ResourceType = "Protocol"

		if policyEnabled == tp.KubeArmorPolicyAudited && npt.Action == "Allow" {
			match.Action = "Audit (" + npt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && npt.Action == "Block" {
			match.Action = "Audit (" + npt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyEnabled && fd.IsGKE && npt.Action == "Block" {
			match.Action = "Audit (" + npt.Action + ")"
		} else {
			match.Action = npt.Action
		}
	} else if cct, ok := mp.(tp.CapabilitiesCapabilityType); ok {
		match.Severity = strconv.Itoa(cct.Severity)
		match.Tags = cct.Tags
		match.Message = cct.Message

		op, cap := getOperationAndCapabilityFromName(cct.Capability)

		match.Operation = op
		match.Resource = cap
		match.ResourceType = "Capability"

		if policyEnabled == tp.KubeArmorPolicyAudited && cct.Action == "Allow" {
			match.Action = "Audit (" + cct.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && cct.Action == "Block" {
			match.Action = "Audit (" + cct.Action + ")"
		} else {
			match.Action = cct.Action
		}
	} else {
		return tp.MatchPolicy{}
	}

	return match
}

// UpdateSecurityPolicies Function
func (fd *Feeder) UpdateSecurityPolicies(action string, endPoint tp.EndPoint) {
	name := endPoint.NamespaceName + "_" + endPoint.EndPointName

	if action == "DELETED" {
		delete(fd.SecurityPolicies, name)
		return
	}

	// ADDED | MODIFIED
	matches := tp.MatchPolicies{}

	for _, secPolicy := range endPoint.SecurityPolicies {
		policyName := secPolicy.Metadata["policyName"]

		if len(secPolicy.Spec.AppArmor) > 0 {
			continue
		}

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.Process.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				fd.Debugf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.File.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				fd.Debugf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.Protocol) == 0 {
				continue
			}

			fromSource := ""

			if len(proto.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range proto.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}

		}

		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.Capability) == 0 {
				continue
			}

			fromSource := ""

			if len(cap.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range cap.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}
	}

	fd.SecurityPoliciesLock.Lock()
	fd.SecurityPolicies[name] = matches
	fd.SecurityPoliciesLock.Unlock()
}

// ============================ //
// == Host Security Policies == //
// ============================ //

// UpdateHostSecurityPolicies Function
func (fd *Feeder) UpdateHostSecurityPolicies(action string, secPolicies []tp.HostSecurityPolicy) {
	if action == "DELETED" {
		delete(fd.SecurityPolicies, fd.Node.NodeName)
		return
	}

	// ADDED | MODIFIED
	matches := tp.MatchPolicies{}

	for _, secPolicy := range secPolicies {
		policyName := secPolicy.Metadata["policyName"]

		if len(secPolicy.Spec.AppArmor) > 0 {
			continue
		}

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.Process.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(tp.KubeArmorPolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				fd.Debugf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.File.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				fd.Debugf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.Protocol) == 0 {
				continue
			}

			fromSource := ""

			if len(proto.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range proto.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if len(cap.Capability) == 0 {
				continue
			}

			fromSource := ""

			if len(cap.FromSource) == 0 {
				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range cap.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(fd.Node.PolicyEnabled, policyName, fromSource, cap)
				if len(match.Resource) == 0 {
					continue
				}
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}
	}

	fd.SecurityPoliciesLock.Lock()
	fd.SecurityPolicies[fd.Node.NodeName] = matches
	fd.SecurityPoliciesLock.Unlock()
}

// ===================== //
// == Default Posture == //
// ===================== //

// UpdateDefaultPosture Function
func (fd *Feeder) UpdateDefaultPosture(action string, namespace string, defaultPosture tp.DefaultPosture) {

	fd.DefaultPosturesLock.Lock()
	defer fd.DefaultPosturesLock.Unlock()

	if action == "DELETED" {
		delete(fd.DefaultPostures, namespace)
	} else { // ADDED or MODIFIED
		fd.DefaultPostures[namespace] = defaultPosture
	}
}

// Update Log Fields based on default posture and visibility configuration and return false if no updates
func setLogFields(log *tp.Log, action string, considerPosture, visibility, containerLog bool) bool {
	if considerPosture && action == "block" {
		if containerLog {
			(*log).Type = "MatchedPolicy"
		} else {
			(*log).Type = "MatchedHostPolicy"
		}
		(*log).PolicyName = "DefaultPosture"
		(*log).Action = "Block"
		return true
	} else if considerPosture && action == "audit" {
		if containerLog {
			(*log).Type = "MatchedPolicy"
		} else {
			(*log).Type = "MatchedHostPolicy"
		}
		(*log).PolicyName = "DefaultPosture"
		(*log).Action = "Audit"
		return true
	} else if visibility {
		if containerLog {
			(*log).Type = "ContainerLog"
		} else {
			(*log).Type = "HostLog"
		}
		return true
	}
	return false
}

// ==================== //
// == Policy Matches == //
// ==================== //

func getDirectoryPart(path string) string {
	dirs := strings.Split(path, "/")
	if len(dirs) > 1 {
		return strings.Join(dirs[0:len(dirs)-2], "/")
	}
	return "__no_directory__"
}

// UpdateMatchedPolicy Function
func (fd *Feeder) UpdateMatchedPolicy(log tp.Log) tp.Log {
	allowProcPolicy := ""
	allowProcPolicySeverity := ""
	allowProcTags := []string{}
	allowProcMessage := ""

	allowFilePolicy := ""
	allowFilePolicySeverity := ""
	allowFileTags := []string{}
	allowFileMessage := ""

	allowNetworkPolicy := ""
	allowNetworkPolicySeverity := ""
	allowNetworkTags := []string{}
	allowNetworkMessage := ""

	considerFilePosture := false
	considerNetworkPosture := false

	if log.Result == "Passed" || log.Result == "Operation not permitted" || log.Result == "Permission denied" {
		fd.SecurityPoliciesLock.RLock()

		key := cfg.GlobalCfg.Host

		if log.NamespaceName != "" && log.PodName != "" {
			key = log.NamespaceName + "_" + log.PodName
		}

		secPolicies := fd.SecurityPolicies[key].Policies
		for _, secPolicy := range secPolicies {
			firstLogSource := strings.Replace(strings.Split(log.Source, " ")[0], "./", "", 1)
			firstLogResource := strings.Replace(strings.Split(log.Resource, " ")[0], "./", "", 1)

			if strings.Contains(secPolicy.Action, "Allow") {
				if secPolicy.Source == "" || (secPolicy.IsFromSource &&
					((secPolicy.Operation == "Process" && (secPolicy.Source == log.ParentProcessName || secPolicy.Source == log.ProcessName)) || // ./bash -> xxx || ./bash -c xxx
						(secPolicy.Operation != "Process" && (secPolicy.Source == log.ProcessName || strings.Contains(secPolicy.Source, firstLogSource))))) {

					if secPolicy.Operation == "Process" {
						if allowProcPolicy == "" {
							allowProcPolicy = secPolicy.PolicyName
							allowProcPolicySeverity = secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowProcTags, tag) {
									allowProcTags = append(allowProcTags, tag)
								}
							}

							allowProcMessage = secPolicy.Message
						} else if !strings.Contains(allowProcPolicy, secPolicy.PolicyName) {
							allowProcPolicy = allowProcPolicy + "," + secPolicy.PolicyName
							allowProcPolicySeverity = allowProcPolicySeverity + "," + secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowProcTags, tag) {
									allowProcTags = append(allowProcTags, tag)
								}
							}

							allowProcMessage = allowProcMessage + "," + secPolicy.Message
						}
					} else if secPolicy.Operation == "File" {
						if allowFilePolicy == "" {
							allowFilePolicy = secPolicy.PolicyName
							allowFilePolicySeverity = secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowFileTags, tag) {
									allowFileTags = append(allowFileTags, tag)
								}
							}

							allowFileMessage = secPolicy.Message
						} else if !strings.Contains(allowFilePolicy, secPolicy.PolicyName) {
							allowFilePolicy = allowFilePolicy + "," + secPolicy.PolicyName
							allowFilePolicySeverity = allowFilePolicySeverity + "," + secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowFileTags, tag) {
									allowFileTags = append(allowFileTags, tag)
								}
							}

							allowFileMessage = allowFileMessage + "," + secPolicy.Message
						}
					} else if secPolicy.Operation == "Network" {
						if allowNetworkPolicy == "" {
							allowNetworkPolicy = secPolicy.PolicyName
							allowNetworkPolicySeverity = secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowNetworkTags, tag) {
									allowNetworkTags = append(allowNetworkTags, tag)
								}
							}

							allowNetworkMessage = secPolicy.Message
						} else if !strings.Contains(allowNetworkPolicy, secPolicy.PolicyName) {
							allowNetworkPolicy = allowNetworkPolicy + "," + secPolicy.PolicyName
							allowNetworkPolicySeverity = allowNetworkPolicySeverity + "," + secPolicy.Severity

							for _, tag := range secPolicy.Tags {
								if !kl.ContainsElement(allowNetworkTags, tag) {
									allowNetworkTags = append(allowNetworkTags, tag)
								}
							}

							allowNetworkMessage = allowNetworkMessage + "," + secPolicy.Message
						}
					}
				}
			}

			switch log.Operation {
			case "Process", "File":
				if secPolicy.Operation == log.Operation {
					matched := false

					switch secPolicy.ResourceType {
					case "Glob":
						// Match using a globbing syntax very similar to the AppArmor's
						matched, _ = filepath.Match(secPolicy.Resource, log.Resource) // pattern (secPolicy.Resource) -> string (log.Resource)
					case "Regexp":
						if secPolicy.Regexp != nil {
							// Match using compiled regular expression
							matched = secPolicy.Regexp.MatchString(log.Resource) // regexp (secPolicy.Regexp) -> string (log.Resource)
						}
					}

					if secPolicy.Source == "" || (secPolicy.IsFromSource &&
						((secPolicy.Operation == "Process" && (secPolicy.Source == log.ParentProcessName || secPolicy.Source == log.ProcessName)) || // ./bash -> xxx || ./bash -c xxx
							(secPolicy.Operation == "File" && (secPolicy.Source == log.ProcessName || strings.Contains(secPolicy.Source, firstLogSource))))) {

						if matched ||
							(secPolicy.ResourceType == "Path" && secPolicy.Resource == log.Resource) || // exact path match
							(secPolicy.ResourceType == "Path" && strings.HasSuffix(secPolicy.Resource, firstLogResource)) || // file name match
							(secPolicy.ResourceType == "Directory" && strings.HasPrefix(log.Resource, secPolicy.Resource)) || // exact directory match (non-recursive and recursive)
							(secPolicy.ResourceType == "Directory" && strings.HasSuffix(secPolicy.Resource, getDirectoryPart(firstLogResource))) { // surffix match (non-recurisve)

							matchedFlags := false

							if (secPolicy.Action == "Audit" && log.Result == "Passed") || (log.PolicyEnabled == tp.KubeArmorPolicyAudited && strings.Contains(secPolicy.Action, "Allow")) {
								if secPolicy.ReadOnly && log.Resource != "" && secPolicy.OwnerOnly && log.MergedDir != "" {
									// read only && owner only
									if strings.Contains(log.Data, "O_RDONLY") && strconv.Itoa(int(log.UID)) == getFileProcessUID(log.MergedDir+log.Resource) {
										matchedFlags = true
									}
								} else if secPolicy.ReadOnly && log.Resource != "" {
									// read only
									if strings.Contains(log.Data, "O_RDONLY") {
										matchedFlags = true
									}
								} else if secPolicy.OwnerOnly && log.MergedDir != "" {
									// owner only
									if strconv.Itoa(int(log.UID)) == getFileProcessUID(log.MergedDir+log.Resource) {
										matchedFlags = true
									}
								} else {
									// ! read only && ! owner only
									matchedFlags = true
								}

							} else if log.PolicyEnabled == tp.KubeArmorPolicyAudited && strings.Contains(secPolicy.Action, "Block") {
								if secPolicy.ReadOnly && log.Resource != "" && secPolicy.OwnerOnly && log.MergedDir != "" {
									// read only && owner only
									if strings.Contains(log.Data, "O_RDONLY") && strconv.Itoa(int(log.UID)) == getFileProcessUID(log.MergedDir+log.Resource) {
										matchedFlags = true
									}
								} else if secPolicy.ReadOnly && log.Resource != "" {
									// read only
									if strings.Contains(log.Data, "O_RDONLY") {
										matchedFlags = true
									}
								} else if secPolicy.OwnerOnly && log.MergedDir != "" {
									// owner only
									if strconv.Itoa(int(log.UID)) == getFileProcessUID(log.MergedDir+log.Resource) {
										matchedFlags = true
									}
								}
								// otherwise, being supposed to be blocked
							}

							if (matchedFlags && secPolicy.Action == "Audit" && log.Result == "Passed") || (!matchedFlags && log.PolicyEnabled == tp.KubeArmorPolicyAudited && (strings.Contains(secPolicy.Action, "Allow") || strings.Contains(secPolicy.Action, "Block"))) {
								log.Type = "MatchedPolicy"

								log.PolicyName = secPolicy.PolicyName
								log.Severity = secPolicy.Severity

								if len(secPolicy.Tags) > 0 {
									log.Tags = strings.Join(secPolicy.Tags[:], ",")
								}

								if len(secPolicy.Message) > 0 {
									log.Message = secPolicy.Message
								}

								if secPolicy.Action == "Audit" || log.PolicyEnabled == tp.KubeArmorPolicyAudited {
									log.Enforcer = "eBPF Monitor"
								} else {
									log.Enforcer = fd.Enforcer
								}

								log.Action = secPolicy.Action

								continue
							}

							if log.PolicyEnabled == tp.KubeArmorPolicyEnabled && log.Result != "Passed" {
								log.Type = "MatchedPolicy"

								log.PolicyName = secPolicy.PolicyName
								log.Severity = secPolicy.Severity

								if len(secPolicy.Tags) > 0 {
									log.Tags = strings.Join(secPolicy.Tags[:], ",")
								}

								if len(secPolicy.Message) > 0 {
									log.Message = secPolicy.Message
								}

								log.Enforcer = fd.Enforcer
								log.Action = secPolicy.Action

								continue
							}
						}
					}
				}
			case "Network":
				if secPolicy.Operation == log.Operation {
					if secPolicy.Source == "" || (secPolicy.IsFromSource && (secPolicy.Source == log.ProcessName || strings.Contains(secPolicy.Source, firstLogSource))) {

						if strings.Contains(log.Resource, secPolicy.Resource) {

							if (log.PolicyEnabled == tp.KubeArmorPolicyEnabled && log.Result != "Passed") || (secPolicy.Action == "Audit" && log.Result == "Passed") || (log.PolicyEnabled == tp.KubeArmorPolicyAudited && strings.Contains(secPolicy.Action, "Block")) {
								log.Type = "MatchedPolicy"

								log.PolicyName = secPolicy.PolicyName
								log.Severity = secPolicy.Severity

								if len(secPolicy.Tags) > 0 {
									log.Tags = strings.Join(secPolicy.Tags[:], ",")
								}

								if len(secPolicy.Message) > 0 {
									log.Message = secPolicy.Message
								}

								if secPolicy.Action == "Audit" || log.PolicyEnabled == tp.KubeArmorPolicyAudited {
									log.Enforcer = "eBPF Monitor"
								} else {
									log.Enforcer = fd.Enforcer
								}

								log.Action = secPolicy.Action

								continue
							}
						}
					}
				}
			}
		}

		fd.SecurityPoliciesLock.RUnlock()

		if log.Result == "Operation not permitted" || log.Result == "Permission denied" {
			if log.Operation == "Process" && allowProcPolicy == "" {
				considerFilePosture = true
			} else if log.Operation == "File" && allowFilePolicy == "" {
				considerFilePosture = true
			} else if log.Operation == "Network" && allowNetworkPolicy == "" {
				considerNetworkPosture = true
			}
		}
	}

	if log.ContainerID != "" { // container
		if log.Type == "" {
			if (log.PolicyEnabled == tp.KubeArmorPolicyEnabled && log.Result != "Passed") || (log.PolicyEnabled == tp.KubeArmorPolicyAudited) {
				if log.Operation == "Process" && allowProcPolicy != "" {
					log.Type = "MatchedPolicy"

					log.PolicyName = allowProcPolicy
					log.Severity = allowProcPolicySeverity

					if len(allowProcTags) > 0 {
						log.Tags = strings.Join(allowProcTags[:], ",")
					}

					if len(allowProcMessage) > 0 {
						log.Message = allowProcMessage
					}

					if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
						log.Enforcer = "eBPF Monitor"
						log.Action = "Audit (Allow)"
					} else {
						log.Enforcer = fd.Enforcer
						log.Action = "Allow"
					}

					return log

				} else if log.Operation == "File" && allowFilePolicy != "" {
					log.Type = "MatchedPolicy"

					log.PolicyName = allowFilePolicy
					log.Severity = allowFilePolicySeverity

					if len(allowFileTags) > 0 {
						log.Tags = strings.Join(allowFileTags[:], ",")
					}

					if len(allowFileMessage) > 0 {
						log.Message = allowFileMessage
					}

					if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
						log.Enforcer = "eBPF Monitor"
						log.Action = "Audit (Allow)"
					} else {
						log.Enforcer = fd.Enforcer
						log.Action = "Allow"
					}

					return log

				} else if log.Operation == "Network" && allowNetworkPolicy != "" {
					log.Type = "MatchedPolicy"

					log.PolicyName = allowNetworkPolicy
					log.Severity = allowNetworkPolicySeverity

					if len(allowNetworkTags) > 0 {
						log.Tags = strings.Join(allowNetworkTags[:], ",")
					}

					if len(allowNetworkMessage) > 0 {
						log.Message = allowNetworkMessage
					}

					if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
						log.Enforcer = "eBPF Monitor"
						log.Action = "Audit (Allow)"
					} else {
						log.Enforcer = fd.Enforcer
						log.Action = "Allow"
					}

					return log
				}
			}

			fd.DefaultPosturesLock.Lock()
			defer fd.DefaultPosturesLock.Unlock()

			if _, ok := fd.DefaultPostures[log.NamespaceName]; !ok {
				globalDefaultPosture := tp.DefaultPosture{
					FileAction:         cfg.GlobalCfg.DefaultFilePosture,
					NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
					CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
				}
				fd.DefaultPostures[log.NamespaceName] = globalDefaultPosture
			}

			if log.Operation == "Process" {
				if setLogFields(&log, fd.DefaultPostures[log.NamespaceName].FileAction, considerFilePosture, log.ProcessVisibilityEnabled, true) {
					return log
				}
			} else if log.Operation == "File" {
				if setLogFields(&log, fd.DefaultPostures[log.NamespaceName].FileAction, considerFilePosture, log.FileVisibilityEnabled, true) {
					return log
				}
			} else if log.Operation == "Network" {
				if setLogFields(&log, fd.DefaultPostures[log.NamespaceName].NetworkAction, considerNetworkPosture, log.NetworkVisibilityEnabled, true) {
					return log
				}
			} else if log.Operation == "Capabilities" {
				if setLogFields(&log, fd.DefaultPostures[log.NamespaceName].CapabilitiesAction, false, log.CapabilitiesVisibilityEnabled, true) {
					return log
				}
			}

		} else if log.Type == "MatchedPolicy" {
			if log.Action == "Allow" && log.Result == "Passed" {
				return tp.Log{}
			}
			return log
		}
	} else { // host
		if log.Type == "" {
			if (log.PolicyEnabled == tp.KubeArmorPolicyEnabled && log.Result != "Passed") || (log.PolicyEnabled == tp.KubeArmorPolicyAudited) {
				if log.Operation == "Process" && allowProcPolicy != "" {
					log.Type = "MatchedHostPolicy"

					log.PolicyName = allowProcPolicy
					log.Severity = allowProcPolicySeverity

					if len(allowProcTags) > 0 {
						log.Tags = strings.Join(allowProcTags[:], ",")
					}

					if len(allowProcMessage) > 0 {
						log.Message = allowProcMessage
					}

					if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
						log.Enforcer = "eBPF Monitor"
						log.Action = "Audit (Allow)"
					} else {
						log.Enforcer = fd.Enforcer
						log.Action = "Allow"
					}

					return log

				} else if log.Operation == "File" && allowFilePolicy != "" {
					log.Type = "MatchedHostPolicy"

					log.PolicyName = allowFilePolicy
					log.Severity = allowFilePolicySeverity

					if len(allowFileTags) > 0 {
						log.Tags = strings.Join(allowFileTags[:], ",")
					}

					if len(allowFileMessage) > 0 {
						log.Message = allowFileMessage
					}

					if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
						log.Enforcer = "eBPF Monitor"
						log.Action = "Audit (Allow)"
					} else {
						log.Enforcer = fd.Enforcer
						log.Action = "Allow"
					}

					return log

				} else if log.Operation == "Network" && allowNetworkPolicy != "" {
					log.Type = "MatchedHostPolicy"

					log.PolicyName = allowNetworkPolicy
					log.Severity = allowNetworkPolicySeverity

					if len(allowNetworkTags) > 0 {
						log.Tags = strings.Join(allowNetworkTags[:], ",")
					}

					if len(allowNetworkMessage) > 0 {
						log.Message = allowNetworkMessage
					}

					if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
						log.Enforcer = "eBPF Monitor"
						log.Action = "Audit (Allow)"
					} else {
						log.Enforcer = fd.Enforcer
						log.Action = "Allow"
					}

					return log
				}
			}

			if log.Result == "Operation not permitted" || log.Result == "Permission denied" {
				if log.Operation == "Process" && allowProcPolicy == "" {
					considerFilePosture = true
				} else if log.Operation == "File" && allowFilePolicy == "" {
					considerFilePosture = true
				} else if log.Operation == "Network" && allowNetworkPolicy == "" {
					considerNetworkPosture = true
				}
			}

			if log.Operation == "Process" {
				if setLogFields(&log, "block", considerFilePosture, fd.Node.ProcessVisibilityEnabled, false) {
					return log
				}
			} else if log.Operation == "File" {
				if setLogFields(&log, "block", considerFilePosture, fd.Node.FileVisibilityEnabled, false) {
					return log
				}
			} else if log.Operation == "Network" {
				if setLogFields(&log, "block", considerNetworkPosture, fd.Node.NetworkVisibilityEnabled, false) {
					return log
				}
			} else if log.Operation == "Capabilities" {
				if setLogFields(&log, "block", false, fd.Node.CapabilitiesVisibilityEnabled, false) {
					return log
				}
			}

		} else if log.Type == "MatchedPolicy" {
			log.Type = "MatchedHostPolicy"

			if log.Action == "Allow" && log.Result == "Passed" {
				return tp.Log{}
			}

			return log
		}
	}

	return tp.Log{}
}
