package feeder

import (
	"strconv"
	"strings"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ======================= //
// == Security Policies == //
// ======================= //

func newProcPathMatchPolicy(policyName, source string, path tp.ProcessPathType) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Severity:   strconv.Itoa(path.Severity),
		Tags:       path.Tags,
		Message:    path.Message,
		Source:     source,
		Operation:  "Process",
		Resource:   path.Path,
		Action:     path.Action,
	}

	return match
}

func newProcDirMatchPolicy(policyName, source string, dir tp.ProcessDirectoryType) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Severity:   strconv.Itoa(dir.Severity),
		Tags:       dir.Tags,
		Message:    dir.Message,
		Source:     source,
		Operation:  "Process",
		Resource:   dir.Directory,
		Action:     dir.Action,
	}

	return match
}

func newFilePathMatchPolicy(policyName, source string, path tp.FilePathType) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Severity:   strconv.Itoa(path.Severity),
		Tags:       path.Tags,
		Message:    path.Message,
		Source:     source,
		Operation:  "File",
		Resource:   path.Path,
		Action:     path.Action,
	}

	return match
}

func newFileDirMatchPolicy(policyName, source string, dir tp.FileDirectoryType) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Severity:   strconv.Itoa(dir.Severity),
		Tags:       dir.Tags,
		Message:    dir.Message,
		Source:     source,
		Operation:  "File",
		Resource:   dir.Directory,
		Action:     dir.Action,
	}

	return match
}

func newNetProtMatchPolicy(policyName, source, resource string, netProt tp.NetworkProtocolType) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Severity:   strconv.Itoa(netProt.Severity),
		Tags:       netProt.Tags,
		Message:    netProt.Message,
		Source:     source,
		Operation:  "Network",
		Resource:   resource,
		Action:     netProt.Action,
	}

	return match
}

func getProtocolFromName(proto string) string {
	switch strings.ToLower(proto) {
	case "tcp":
		return "type=SOCK_STREAM"
	case "udp":
		return "type=SOCK_DGRAM"
	case "icmp":
		return "type=SOCK_RAW protocol=1"
	default:
		return ""
	}
}

func newCapMatchPolicy(policyName, source, resource string, cap tp.CapabilitiesCapabilityType) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Severity:   strconv.Itoa(cap.Severity),
		Tags:       cap.Tags,
		Message:    cap.Message,
		Source:     source,
		Operation:  "Network",
		Resource:   resource,
		Action:     cap.Action,
	}

	return match
}

func getCapabilityFromName(cap string) string {
	switch strings.ToLower(cap) {
	case "net_raw":
		return "type=SOCK_RAW protocol=1"
	default:
		return ""
	}
}

// UpdateSecurityPolicies Function
func (fd *Feeder) UpdateSecurityPolicies(action string, conGroup tp.ContainerGroup) {
	name := conGroup.NamespaceName + "_" + conGroup.ContainerGroupName

	if action == "DELETED" {
		delete(fd.SecurityPolicies, name)
		return
	}

	// ADDED | MODIFIED
	matches := tp.MatchPolicies{}

	for _, secPolicy := range conGroup.SecurityPolicies {
		policyName := secPolicy.Metadata["policyName"]

		if len(secPolicy.Spec.AppArmor) > 0 {
			match := tp.MatchPolicy{}

			match.PolicyName = policyName
			match.Native = true

			matches.Policies = append(matches.Policies, match)
			continue
		}

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := newProcPathMatchPolicy(policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := newProcPathMatchPolicy(policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := newProcDirMatchPolicy(policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := newProcDirMatchPolicy(policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
			}
		}

		// for _, patt := range secPolicy.Spec.Process.MatchPatterns {
		// }

		for _, path := range secPolicy.Spec.File.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := newFilePathMatchPolicy(policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := newFilePathMatchPolicy(policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := newFileDirMatchPolicy(policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := newFileDirMatchPolicy(policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
			}
		}

		// for _, patt := range secPolicy.Spec.File.MatchPatterns {
		// }

		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			res := getProtocolFromName(proto.Protocol)
			if len(res) == 0 {
				continue
			}

			fromSource := ""

			if len(proto.FromSource) == 0 {
				match := newNetProtMatchPolicy(policyName, fromSource, res, proto)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range proto.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := newNetProtMatchPolicy(policyName, fromSource, res, proto)
				matches.Policies = append(matches.Policies, match)
			}

		}

		for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			res := getCapabilityFromName(cap.Capability)
			if len(res) == 0 {
				continue
			}

			fromSource := ""

			if len(cap.FromSource) == 0 {
				match := newCapMatchPolicy(policyName, fromSource, res, cap)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range cap.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else if len(src.Directory) > 0 {
					fromSource = src.Directory
				} else {
					continue
				}

				match := newCapMatchPolicy(policyName, fromSource, res, cap)
				matches.Policies = append(matches.Policies, match)
			}

		}

		// for _, res := range secPolicy.Spec.Resource.MatchResources {
		// }
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
		delete(fd.SecurityPolicies, fd.HostName)
	} else { // ADDED | MODIFIED
		matches := tp.MatchPolicies{}

		for _, secPolicy := range secPolicies {
			if len(secPolicy.Spec.AppArmor) > 0 {
				match := tp.MatchPolicy{}

				match.PolicyName = secPolicy.Metadata["policyName"]
				match.Native = true

				matches.Policies = append(matches.Policies, match)
				continue
			}

			if len(secPolicy.Spec.Process.MatchPaths) > 0 {
				for _, path := range secPolicy.Spec.Process.MatchPaths {
					if len(path.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]

						match.Severity = strconv.Itoa(path.Severity)
						match.Tags = path.Tags
						match.Message = path.Message

						match.Source = ""
						match.Operation = "Process"
						match.Resource = path.Path

						match.Action = path.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(path.Severity)
								match.Tags = path.Tags
								match.Message = path.Message

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = path.Path

								match.Action = path.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(path.Severity)
								match.Tags = path.Tags
								match.Message = path.Message

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = path.Path

								match.Action = path.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
				for _, dir := range secPolicy.Spec.Process.MatchDirectories {
					if len(dir.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]

						match.Severity = strconv.Itoa(dir.Severity)
						match.Tags = dir.Tags
						match.Message = dir.Message

						match.Source = ""
						match.Operation = "Process"
						match.Resource = dir.Directory

						match.Action = dir.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(dir.Severity)
								match.Tags = dir.Tags
								match.Message = dir.Message

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = dir.Directory

								match.Action = dir.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(dir.Severity)
								match.Tags = dir.Tags
								match.Message = dir.Message

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = dir.Directory

								match.Action = dir.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
				//
			}

			if len(secPolicy.Spec.File.MatchPaths) > 0 {
				for _, path := range secPolicy.Spec.File.MatchPaths {
					if len(path.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]

						match.Severity = strconv.Itoa(path.Severity)
						match.Tags = path.Tags
						match.Message = path.Message

						match.Source = ""
						match.Operation = "File"
						match.Resource = path.Path

						match.Action = path.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(path.Severity)
								match.Tags = path.Tags
								match.Message = path.Message

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = path.Path

								match.Action = path.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(path.Severity)
								match.Tags = path.Tags
								match.Message = path.Message

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = path.Path

								match.Action = path.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.File.MatchDirectories) > 0 {
				for _, dir := range secPolicy.Spec.File.MatchDirectories {
					if len(dir.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]

						match.Severity = strconv.Itoa(dir.Severity)
						match.Tags = dir.Tags
						match.Message = dir.Message

						match.Source = ""
						match.Operation = "File"
						match.Resource = dir.Directory

						match.Action = dir.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(dir.Severity)
								match.Tags = dir.Tags
								match.Message = dir.Message

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = dir.Directory

								match.Action = dir.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(dir.Severity)
								match.Tags = dir.Tags
								match.Message = dir.Message

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = dir.Directory

								match.Action = dir.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.File.MatchPatterns) > 0 {
				//
			}

			if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
				for _, proto := range secPolicy.Spec.Network.MatchProtocols {
					if len(proto.FromSource) != 0 {
						for _, src := range proto.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(proto.Severity)
								match.Tags = proto.Tags
								match.Message = proto.Message

								match.Source = src.Path
								match.Operation = "Network"

								switch proto.Protocol {
								case "TCP", "tcp":
									match.Resource = "type=SOCK_STREAM"

								case "UDP", "udp":
									match.Resource = "type=SOCK_DGRAM"

								case "ICMP", "icmp":
									match.Resource = "type=SOCK_RAW protocol=1"

								default:
									continue
								}

								match.Action = proto.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(proto.Severity)
								match.Tags = proto.Tags
								match.Message = proto.Message

								match.Source = src.Directory
								match.Operation = "Network"

								switch proto.Protocol {
								case "TCP", "tcp":
									match.Resource = "type=SOCK_STREAM"

								case "UDP", "udp":
									match.Resource = "type=SOCK_DGRAM"

								case "ICMP", "icmp":
									match.Resource = "type=SOCK_RAW protocol=1"

								default:
									continue
								}

								match.Action = proto.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
				for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
					if len(cap.FromSource) != 0 {
						for _, src := range cap.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(cap.Severity)
								match.Tags = cap.Tags
								match.Message = cap.Message

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Path
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"

								default:
									continue
								}

								match.Action = cap.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								match.Severity = strconv.Itoa(cap.Severity)
								match.Tags = cap.Tags
								match.Message = cap.Message

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Directory
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"

								default:
									continue
								}

								match.Action = cap.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}
		}

		fd.SecurityPoliciesLock.Lock()
		fd.SecurityPolicies[fd.HostName] = matches
		fd.SecurityPoliciesLock.Unlock()
	}
}

// ==================== //
// == Policy Matches == //
// ==================== //

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

	mightBeNative := false

	if log.Result == "Passed" || log.Result == "Operation not permitted" || log.Result == "Permission denied" {
		fd.SecurityPoliciesLock.RLock()

		key := log.HostName

		if log.NamespaceName != "" && log.PodName != "" {
			key = log.NamespaceName + "_" + log.PodName
		}

		secPolicies := fd.SecurityPolicies[key].Policies
		for _, secPolicy := range secPolicies {
			if secPolicy.Native && log.Result != "Passed" {
				mightBeNative = true
				continue
			}

			if secPolicy.Source == "" || strings.Contains(secPolicy.Source, log.Source) {
				if secPolicy.Action == "Allow" || secPolicy.Action == "AllowWithAudit" {
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
					if strings.HasPrefix(log.Resource, secPolicy.Resource) {
						if secPolicy.Source != "" && strings.Contains(secPolicy.Source, log.Source) {
							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							log.Type = "MatchedPolicy"
							log.Action = secPolicy.Action

							break
						} else if secPolicy.Source == "" {
							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							log.Type = "MatchedPolicy"
							log.Action = secPolicy.Action

							break
						}
					}
				}
			case "Network":
				if secPolicy.Operation == log.Operation {
					if strings.Contains(log.Resource, secPolicy.Resource) {
						if secPolicy.Source != "" && strings.Contains(secPolicy.Source, log.Source) {
							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							log.Type = "MatchedPolicy"
							log.Action = secPolicy.Action

							break
						} else if secPolicy.Source == "" {
							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							log.Type = "MatchedPolicy"
							log.Action = secPolicy.Action

							break
						}
					}
				}
			}
		}

		fd.SecurityPoliciesLock.RUnlock()
	}

	if log.ContainerID != "" { // container
		if log.Type == "" {
			if log.Result != "Passed" {
				if log.Operation == "Process" && allowProcPolicy != "" {
					log.PolicyName = allowProcPolicy
					log.Severity = allowProcPolicySeverity

					if len(allowProcTags) > 0 {
						log.Tags = strings.Join(allowProcTags[:], ",")
					}

					if len(allowProcMessage) > 0 {
						log.Message = allowProcMessage
					}

					log.Type = "MatchedPolicy"
					log.Action = "Allow"

					return log

				} else if log.Operation == "File" && allowFilePolicy != "" {
					log.PolicyName = allowFilePolicy
					log.Severity = allowFilePolicySeverity

					if len(allowFileTags) > 0 {
						log.Tags = strings.Join(allowFileTags[:], ",")
					}

					if len(allowFileMessage) > 0 {
						log.Message = allowFileMessage
					}

					log.Type = "MatchedPolicy"
					log.Action = "Allow"

					return log

				} else if log.Operation == "Network" && allowNetworkPolicy != "" {
					log.PolicyName = allowNetworkPolicy
					log.Severity = allowNetworkPolicySeverity

					if len(allowNetworkTags) > 0 {
						log.Tags = strings.Join(allowNetworkTags[:], ",")
					}

					if len(allowNetworkMessage) > 0 {
						log.Message = allowNetworkMessage
					}

					log.Type = "MatchedPolicy"
					log.Action = "Allow"

					return log

				}

				if mightBeNative {
					log.PolicyName = "NativePolicy"

					log.Severity = "-"
					log.Tags = "-"
					log.Message = "KubeArmor detected a native policy violation"

					log.Type = "MatchedNativePolicy"
					log.Action = "Block"

					return log
				}

				// Failed operations
				if log.ProcessVisibilityEnabled && log.Operation == "Process" {
					log.Type = "ContainerLog"
					return log
				} else if log.FileVisibilityEnabled && log.Operation == "File" {
					log.Type = "ContainerLog"
					return log
				} else if log.NetworkVisibilityEnabled && log.Operation == "Network" {
					log.Type = "ContainerLog"
					return log
				} else if log.CapabilitiesVisibilityEnabled && log.Operation == "Capabilities" {
					log.Type = "ContainerLog"
					return log
				}
			} else {
				if log.Action == "Allow" {
					// use 'AllowWithAudit' to get the logs for allowed operations
					return tp.Log{}
				}

				// Passed operations
				if log.ProcessVisibilityEnabled && log.Operation == "Process" {
					log.Type = "ContainerLog"
					return log
				} else if log.FileVisibilityEnabled && log.Operation == "File" {
					log.Type = "ContainerLog"
					return log
				} else if log.NetworkVisibilityEnabled && log.Operation == "Network" {
					log.Type = "ContainerLog"
					return log
				} else if log.CapabilitiesVisibilityEnabled && log.Operation == "Capabilities" {
					log.Type = "ContainerLog"
					return log
				}
			}
		} else if log.Type == "MatchedPolicy" {
			// if log.Action == "Block" {
			// 	// use 'BlockWithAudit' to get the logs for blocked operations
			// 	return tp.Log{}
			// }

			return log
		}
	} else { // host
		if log.Type == "" {
			if log.Result != "Passed" {
				if log.Operation == "Process" && allowProcPolicy != "" {
					log.PolicyName = allowProcPolicy
					log.Severity = allowProcPolicySeverity

					if len(allowProcTags) > 0 {
						log.Tags = strings.Join(allowProcTags[:], ",")
					}

					if len(allowProcMessage) > 0 {
						log.Message = allowProcMessage
					}

					log.Type = "MatchedHostPolicy"
					log.Action = "Allow"

					return log

				} else if log.Operation == "File" && allowFilePolicy != "" {
					log.PolicyName = allowFilePolicy
					log.Severity = allowFilePolicySeverity

					if len(allowFileTags) > 0 {
						log.Tags = strings.Join(allowFileTags[:], ",")
					}

					if len(allowFileMessage) > 0 {
						log.Message = allowFileMessage
					}

					log.Type = "MatchedHostPolicy"
					log.Action = "Allow"

					return log

				} else if log.Operation == "Network" && allowNetworkPolicy != "" {
					log.PolicyName = allowNetworkPolicy
					log.Severity = allowNetworkPolicySeverity

					if len(allowNetworkTags) > 0 {
						log.Tags = strings.Join(allowNetworkTags[:], ",")
					}

					if len(allowNetworkMessage) > 0 {
						log.Message = allowNetworkMessage
					}

					log.Type = "MatchedHostPolicy"
					log.Action = "Allow"

					return log

				}

				if mightBeNative {
					log.PolicyName = "NativePolicy"

					log.Severity = "-"
					log.Tags = "-"
					log.Message = "KubeArmor detected a native policy violation"

					log.Type = "MatchedNativePolicy"
					log.Action = "Block"

					return log
				}
			} else {
				if log.Action == "Allow" {
					// use 'AllowWithAudit' to get the logs for allowed operations
					return tp.Log{}
				}
			}
		} else if log.Type == "MatchedPolicy" {
			// if log.Action == "Block" {
			// 	// use 'BlockWithAudit' to get the logs for blocked operations
			// 	return tp.Log{}
			// }

			log.Type = "MatchedHostPolicy"
			return log
		}
	}

	return tp.Log{}
}
