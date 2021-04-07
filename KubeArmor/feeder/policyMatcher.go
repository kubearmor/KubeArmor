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

// UpdateSecurityPolicies Function
func (fd *Feeder) UpdateSecurityPolicies(action string, conGroup tp.ContainerGroup) {
	if action == "DELETED" {
		delete(fd.SecurityPolicies, conGroup.NamespaceName+"_"+conGroup.ContainerGroupName)
	} else { // ADDED | MODIFIED
		matches := tp.MatchPolicies{}

		for _, secPolicy := range conGroup.SecurityPolicies {
			if len(secPolicy.Spec.Process.MatchPaths) > 0 {
				for _, path := range secPolicy.Spec.Process.MatchPaths {
					if len(path.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						match.Source = ""
						match.Operation = "Process"
						match.Resource = path.Path
						match.Action = secPolicy.Spec.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = path.Path
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = path.Path
								match.Action = secPolicy.Spec.Action

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
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						match.Source = ""
						match.Operation = "Process"
						match.Resource = dir.Directory
						match.Action = secPolicy.Spec.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = dir.Directory
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = dir.Directory
								match.Action = secPolicy.Spec.Action

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
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						match.Source = ""
						match.Operation = "File"
						match.Resource = path.Path
						match.Action = secPolicy.Spec.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = path.Path
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = path.Path
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.File.MatchPatterns) > 0 {
				//
			}

			if len(secPolicy.Spec.File.MatchDirectories) > 0 {
				for _, dir := range secPolicy.Spec.File.MatchDirectories {
					if len(dir.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						match.Source = ""
						match.Operation = "File"
						match.Resource = dir.Directory
						match.Action = secPolicy.Spec.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = dir.Directory
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = dir.Directory
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
				for _, proto := range secPolicy.Spec.Network.MatchProtocols {
					if len(proto.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						match.Source = ""
						match.Operation = "Network"

						switch proto.Protocol {
						case "TCP", "tcp":
							match.Resource = "type=SOCK_STREAM"
							match.Action = secPolicy.Spec.Action

							matches.Policies = append(matches.Policies, match)
						case "UDP", "udp":
							match.Resource = "type=SOCK_DGRAM"
							match.Action = secPolicy.Spec.Action

							matches.Policies = append(matches.Policies, match)
						case "ICMP", "icmp":
							match.Resource = "type=SOCK_RAW protocol=1"
							match.Action = secPolicy.Spec.Action

							matches.Policies = append(matches.Policies, match)
						}
					} else {
						for _, src := range proto.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "Network"

								switch proto.Protocol {
								case "TCP", "tcp":
									match.Resource = "type=SOCK_STREAM"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								case "UDP", "udp":
									match.Resource = "type=SOCK_DGRAM"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								case "ICMP", "icmp":
									match.Resource = "type=SOCK_RAW protocol=1"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								}
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "Network"

								switch proto.Protocol {
								case "TCP", "tcp":
									match.Resource = "type=SOCK_STREAM"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								case "UDP", "udp":
									match.Resource = "type=SOCK_DGRAM"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								case "ICMP", "icmp":
									match.Resource = "type=SOCK_RAW protocol=1"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								}
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
				for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
					if len(cap.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						switch cap.Capability {
						case "net_raw":
							match.Source = ""
							match.Operation = "Network"
							match.Resource = "type=SOCK_RAW protocol=1"
							match.Action = secPolicy.Spec.Action

							matches.Policies = append(matches.Policies, match)
						}
					} else {
						for _, src := range cap.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Path
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								}
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Directory
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								}
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.Resource.MatchResources) > 0 {
				//
			}
		}

		name := conGroup.NamespaceName + "_" + conGroup.ContainerGroupName

		fd.SecurityPoliciesLock.Lock()
		fd.SecurityPolicies[name] = matches
		fd.SecurityPoliciesLock.Unlock()
	}
}

// ============================ //
// == Host Security Policies == //
// ============================ //

// UpdateHostSecurityPolicies Function
func (fd *Feeder) UpdateHostSecurityPolicies(action string, secPolicies []tp.HostSecurityPolicy) {
	if action == "DELETED" {
		delete(fd.SecurityPolicies, fd.hostName)
	} else { // ADDED | MODIFIED
		matches := tp.MatchPolicies{}

		for _, secPolicy := range secPolicies {
			if len(secPolicy.Spec.Process.MatchPaths) > 0 {
				for _, path := range secPolicy.Spec.Process.MatchPaths {
					if len(path.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						match.Source = ""
						match.Operation = "Process"
						match.Resource = path.Path
						match.Action = secPolicy.Spec.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = path.Path
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = path.Path
								match.Action = secPolicy.Spec.Action

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
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						match.Source = ""
						match.Operation = "Process"
						match.Resource = dir.Directory
						match.Action = secPolicy.Spec.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = dir.Directory
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = dir.Directory
								match.Action = secPolicy.Spec.Action

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
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						match.Source = ""
						match.Operation = "File"
						match.Resource = path.Path
						match.Action = secPolicy.Spec.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = path.Path
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = path.Path
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.File.MatchPatterns) > 0 {
				//
			}

			if len(secPolicy.Spec.File.MatchDirectories) > 0 {
				for _, dir := range secPolicy.Spec.File.MatchDirectories {
					if len(dir.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]
						match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

						match.Tags = secPolicy.Spec.Tags
						match.Message = secPolicy.Spec.Message

						match.Source = ""
						match.Operation = "File"
						match.Resource = dir.Directory
						match.Action = secPolicy.Spec.Action

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = dir.Directory
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = dir.Directory
								match.Action = secPolicy.Spec.Action

								matches.Policies = append(matches.Policies, match)
							}
						}
					}
				}
			}

			if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
				for _, proto := range secPolicy.Spec.Network.MatchProtocols {
					if len(proto.FromSource) != 0 {
						for _, src := range proto.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Path
								match.Operation = "Network"

								switch proto.Protocol {
								case "TCP", "tcp":
									match.Resource = "type=SOCK_STREAM"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								case "UDP", "udp":
									match.Resource = "type=SOCK_DGRAM"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								case "ICMP", "icmp":
									match.Resource = "type=SOCK_RAW protocol=1"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								}
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								match.Source = src.Directory
								match.Operation = "Network"

								switch proto.Protocol {
								case "TCP", "tcp":
									match.Resource = "type=SOCK_STREAM"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								case "UDP", "udp":
									match.Resource = "type=SOCK_DGRAM"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								case "ICMP", "icmp":
									match.Resource = "type=SOCK_RAW protocol=1"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								}
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
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Path
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								}
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]
								match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

								match.Tags = secPolicy.Spec.Tags
								match.Message = secPolicy.Spec.Message

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Directory
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"
									match.Action = secPolicy.Spec.Action

									matches.Policies = append(matches.Policies, match)
								}
							}
						}
					}
				}
			}
		}

		fd.SecurityPoliciesLock.Lock()
		fd.SecurityPolicies[fd.hostName] = matches
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

	if log.Result == "Passed" || log.Result == "Operation not permitted" || log.Result == "Permission denied" {
		fd.SecurityPoliciesLock.Lock()

		key := log.HostName

		if log.NamespaceName != "" && log.PodName != "" {
			key = log.NamespaceName + "_" + log.PodName
		}

		secPolicies := fd.SecurityPolicies[key].Policies
		for _, secPolicy := range secPolicies {
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

							log.Type = "PolicyMatched"
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

							log.Type = "PolicyMatched"
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

							log.Type = "PolicyMatched"
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

							log.Type = "PolicyMatched"
							log.Action = secPolicy.Action

							break
						}
					}
				}
			}
		}

		fd.SecurityPoliciesLock.Unlock()
	}

	// use 'AllowWithAudit' to get the logs for allowed operations
	if log.Action == "Allow" && log.Result == "Passed" {
		return tp.Log{}
	}

	// // use 'BlockWithAudit' to get the logs for blocked operations
	// if log.Action == "Block" && log.Result != "Passed" {
	// 	return tp.Log{}
	// }

	if log.NamespaceName != "" { // container
		if log.Type == "" && log.Result != "Passed" {
			if log.Operation == "Process" && allowProcPolicy != "" {
				log.PolicyName = allowProcPolicy
				log.Severity = allowProcPolicySeverity

				if len(allowProcTags) > 0 {
					log.Tags = strings.Join(allowProcTags[:], ",")
				}

				if len(allowProcMessage) > 0 {
					log.Message = allowProcMessage
				}

				log.Type = "PolicyMatched"
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

				log.Type = "PolicyMatched"
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

				log.Type = "PolicyMatched"
				log.Action = "Allow"

				return log
			} else if log.NamespaceName != "" {
				log.Type = "ContainerLog"
				return log
			}
		} else if log.Type == "PolicyMatched" {
			return log
		}
	} else { // host
		if log.Type == "" && log.Result != "Passed" {
			if log.Operation == "Process" && allowProcPolicy != "" {
				log.PolicyName = allowProcPolicy
				log.Severity = allowProcPolicySeverity

				if len(allowProcTags) > 0 {
					log.Tags = strings.Join(allowProcTags[:], ",")
				}

				if len(allowProcMessage) > 0 {
					log.Message = allowProcMessage
				}

				log.Type = "HostPolicyMatched"
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

				log.Type = "HostPolicyMatched"
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

				log.Type = "HostPolicyMatched"
				log.Action = "Allow"

				return log
			} else if log.NamespaceName != "" {
				log.Type = "HostLog"
				return log
			}
		} else if log.Type == "PolicyMatched" {
			log.Type = "HostPolicyMatched"
			return log
		}
	}

	return tp.Log{}
}
