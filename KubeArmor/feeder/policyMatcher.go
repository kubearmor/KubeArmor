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

						if path.Severity > 0 {
							match.Severity = strconv.Itoa(path.Severity)
						} else if secPolicy.Spec.Process.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(path.Tags) > 0 {
							match.Tags = path.Tags
						} else if len(secPolicy.Spec.Process.Tags) > 0 {
							match.Tags = secPolicy.Spec.Process.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(path.Message) > 0 {
							match.Message = path.Message
						} else if len(secPolicy.Spec.Process.Message) > 0 {
							match.Message = secPolicy.Spec.Process.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						match.Source = ""
						match.Operation = "Process"
						match.Resource = path.Path

						if len(path.Action) > 0 {
							match.Action = path.Action
						} else if len(secPolicy.Spec.Process.Action) > 0 {
							match.Action = secPolicy.Spec.Process.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if path.Severity > 0 {
									match.Severity = strconv.Itoa(path.Severity)
								} else if secPolicy.Spec.Process.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(path.Tags) > 0 {
									match.Tags = path.Tags
								} else if len(secPolicy.Spec.Process.Tags) > 0 {
									match.Tags = secPolicy.Spec.Process.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(path.Message) > 0 {
									match.Message = path.Message
								} else if len(secPolicy.Spec.Process.Message) > 0 {
									match.Message = secPolicy.Spec.Process.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = path.Path

								if len(path.Action) > 0 {
									match.Action = path.Action
								} else if len(secPolicy.Spec.Process.Action) > 0 {
									match.Action = secPolicy.Spec.Process.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if path.Severity > 0 {
									match.Severity = strconv.Itoa(path.Severity)
								} else if secPolicy.Spec.Process.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(path.Tags) > 0 {
									match.Tags = path.Tags
								} else if len(secPolicy.Spec.Process.Tags) > 0 {
									match.Tags = secPolicy.Spec.Process.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(path.Message) > 0 {
									match.Message = path.Message
								} else if len(secPolicy.Spec.Process.Message) > 0 {
									match.Message = secPolicy.Spec.Process.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = path.Path

								if len(path.Action) > 0 {
									match.Action = path.Action
								} else if len(secPolicy.Spec.Process.Action) > 0 {
									match.Action = secPolicy.Spec.Process.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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

						if dir.Severity > 0 {
							match.Severity = strconv.Itoa(dir.Severity)
						} else if secPolicy.Spec.Process.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(dir.Tags) > 0 {
							match.Tags = dir.Tags
						} else if len(secPolicy.Spec.Process.Tags) > 0 {
							match.Tags = secPolicy.Spec.Process.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(dir.Message) > 0 {
							match.Message = dir.Message
						} else if len(secPolicy.Spec.Process.Message) > 0 {
							match.Message = secPolicy.Spec.Process.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						match.Source = ""
						match.Operation = "Process"
						match.Resource = dir.Directory

						if len(dir.Action) > 0 {
							match.Action = dir.Action
						} else if len(secPolicy.Spec.Process.Action) > 0 {
							match.Action = secPolicy.Spec.Process.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if dir.Severity > 0 {
									match.Severity = strconv.Itoa(dir.Severity)
								} else if secPolicy.Spec.Process.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(dir.Tags) > 0 {
									match.Tags = dir.Tags
								} else if len(secPolicy.Spec.Process.Tags) > 0 {
									match.Tags = secPolicy.Spec.Process.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(dir.Message) > 0 {
									match.Message = dir.Message
								} else if len(secPolicy.Spec.Process.Message) > 0 {
									match.Message = secPolicy.Spec.Process.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = dir.Directory

								if len(dir.Action) > 0 {
									match.Action = dir.Action
								} else if len(secPolicy.Spec.Process.Action) > 0 {
									match.Action = secPolicy.Spec.Process.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if dir.Severity > 0 {
									match.Severity = strconv.Itoa(dir.Severity)
								} else if secPolicy.Spec.Process.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(dir.Tags) > 0 {
									match.Tags = dir.Tags
								} else if len(secPolicy.Spec.Process.Tags) > 0 {
									match.Tags = secPolicy.Spec.Process.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(dir.Message) > 0 {
									match.Message = dir.Message
								} else if len(secPolicy.Spec.Process.Message) > 0 {
									match.Message = secPolicy.Spec.Process.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = dir.Directory

								if len(dir.Action) > 0 {
									match.Action = dir.Action
								} else if len(secPolicy.Spec.Process.Action) > 0 {
									match.Action = secPolicy.Spec.Process.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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

						if path.Severity > 0 {
							match.Severity = strconv.Itoa(path.Severity)
						} else if secPolicy.Spec.File.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(path.Tags) > 0 {
							match.Tags = path.Tags
						} else if len(secPolicy.Spec.File.Tags) > 0 {
							match.Tags = secPolicy.Spec.File.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(path.Message) > 0 {
							match.Message = path.Message
						} else if len(secPolicy.Spec.File.Message) > 0 {
							match.Message = secPolicy.Spec.File.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						match.Source = ""
						match.Operation = "File"
						match.Resource = path.Path

						if len(path.Action) > 0 {
							match.Action = path.Action
						} else if len(secPolicy.Spec.File.Action) > 0 {
							match.Action = secPolicy.Spec.File.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if path.Severity > 0 {
									match.Severity = strconv.Itoa(path.Severity)
								} else if secPolicy.Spec.File.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(path.Tags) > 0 {
									match.Tags = path.Tags
								} else if len(secPolicy.Spec.File.Tags) > 0 {
									match.Tags = secPolicy.Spec.File.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(path.Message) > 0 {
									match.Message = path.Message
								} else if len(secPolicy.Spec.File.Message) > 0 {
									match.Message = secPolicy.Spec.File.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = path.Path

								if len(path.Action) > 0 {
									match.Action = path.Action
								} else if len(secPolicy.Spec.File.Action) > 0 {
									match.Action = secPolicy.Spec.File.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if path.Severity > 0 {
									match.Severity = strconv.Itoa(path.Severity)
								} else if secPolicy.Spec.File.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(path.Tags) > 0 {
									match.Tags = path.Tags
								} else if len(secPolicy.Spec.File.Tags) > 0 {
									match.Tags = secPolicy.Spec.File.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(path.Message) > 0 {
									match.Message = path.Message
								} else if len(secPolicy.Spec.File.Message) > 0 {
									match.Message = secPolicy.Spec.File.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = path.Path

								if len(path.Action) > 0 {
									match.Action = path.Action
								} else if len(secPolicy.Spec.File.Action) > 0 {
									match.Action = secPolicy.Spec.File.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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

						if dir.Severity > 0 {
							match.Severity = strconv.Itoa(dir.Severity)
						} else if secPolicy.Spec.File.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(dir.Tags) > 0 {
							match.Tags = dir.Tags
						} else if len(secPolicy.Spec.File.Tags) > 0 {
							match.Tags = secPolicy.Spec.File.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(dir.Message) > 0 {
							match.Message = dir.Message
						} else if len(secPolicy.Spec.File.Message) > 0 {
							match.Message = secPolicy.Spec.File.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						match.Source = ""
						match.Operation = "File"
						match.Resource = dir.Directory

						if len(dir.Action) > 0 {
							match.Action = dir.Action
						} else if len(secPolicy.Spec.File.Action) > 0 {
							match.Action = secPolicy.Spec.File.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if dir.Severity > 0 {
									match.Severity = strconv.Itoa(dir.Severity)
								} else if secPolicy.Spec.File.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(dir.Tags) > 0 {
									match.Tags = dir.Tags
								} else if len(secPolicy.Spec.File.Tags) > 0 {
									match.Tags = secPolicy.Spec.File.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(dir.Message) > 0 {
									match.Message = dir.Message
								} else if len(secPolicy.Spec.File.Message) > 0 {
									match.Message = secPolicy.Spec.File.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = dir.Directory

								if len(dir.Action) > 0 {
									match.Action = dir.Action
								} else if len(secPolicy.Spec.File.Action) > 0 {
									match.Action = secPolicy.Spec.File.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if dir.Severity > 0 {
									match.Severity = strconv.Itoa(dir.Severity)
								} else if secPolicy.Spec.File.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(dir.Tags) > 0 {
									match.Tags = dir.Tags
								} else if len(secPolicy.Spec.File.Tags) > 0 {
									match.Tags = secPolicy.Spec.File.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(dir.Message) > 0 {
									match.Message = dir.Message
								} else if len(secPolicy.Spec.File.Message) > 0 {
									match.Message = secPolicy.Spec.File.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = dir.Directory

								if len(dir.Action) > 0 {
									match.Action = dir.Action
								} else if len(secPolicy.Spec.File.Action) > 0 {
									match.Action = secPolicy.Spec.File.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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
					if len(proto.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]

						if proto.Severity > 0 {
							match.Severity = strconv.Itoa(proto.Severity)
						} else if secPolicy.Spec.Network.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.Network.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(proto.Tags) > 0 {
							match.Tags = proto.Tags
						} else if len(secPolicy.Spec.Network.Tags) > 0 {
							match.Tags = secPolicy.Spec.Network.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(proto.Message) > 0 {
							match.Message = proto.Message
						} else if len(secPolicy.Spec.Network.Message) > 0 {
							match.Message = secPolicy.Spec.Network.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						match.Source = ""
						match.Operation = "Network"

						switch proto.Protocol {
						case "TCP", "tcp":
							match.Resource = "type=SOCK_STREAM"

							matches.Policies = append(matches.Policies, match)
						case "UDP", "udp":
							match.Resource = "type=SOCK_DGRAM"

							matches.Policies = append(matches.Policies, match)
						case "ICMP", "icmp":
							match.Resource = "type=SOCK_RAW protocol=1"

						default:
							continue
						}

						if len(proto.Action) > 0 {
							match.Action = proto.Action
						} else if len(secPolicy.Spec.Network.Action) > 0 {
							match.Action = secPolicy.Spec.Network.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range proto.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if proto.Severity > 0 {
									match.Severity = strconv.Itoa(proto.Severity)
								} else if secPolicy.Spec.Network.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Network.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(proto.Tags) > 0 {
									match.Tags = proto.Tags
								} else if len(secPolicy.Spec.Network.Tags) > 0 {
									match.Tags = secPolicy.Spec.Network.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(proto.Message) > 0 {
									match.Message = proto.Message
								} else if len(secPolicy.Spec.Network.Message) > 0 {
									match.Message = secPolicy.Spec.Network.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

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

								if len(proto.Action) > 0 {
									match.Action = proto.Action
								} else if len(secPolicy.Spec.Network.Action) > 0 {
									match.Action = secPolicy.Spec.Network.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if proto.Severity > 0 {
									match.Severity = strconv.Itoa(proto.Severity)
								} else if secPolicy.Spec.Network.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Network.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(proto.Tags) > 0 {
									match.Tags = proto.Tags
								} else if len(secPolicy.Spec.Network.Tags) > 0 {
									match.Tags = secPolicy.Spec.Network.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(proto.Message) > 0 {
									match.Message = proto.Message
								} else if len(secPolicy.Spec.Network.Message) > 0 {
									match.Message = secPolicy.Spec.Network.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

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

								if len(proto.Action) > 0 {
									match.Action = proto.Action
								} else if len(secPolicy.Spec.Network.Action) > 0 {
									match.Action = secPolicy.Spec.Network.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
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

						if cap.Severity > 0 {
							match.Severity = strconv.Itoa(cap.Severity)
						} else if secPolicy.Spec.Capabilities.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.Capabilities.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(cap.Tags) > 0 {
							match.Tags = cap.Tags
						} else if len(secPolicy.Spec.Capabilities.Tags) > 0 {
							match.Tags = secPolicy.Spec.Capabilities.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(cap.Message) > 0 {
							match.Message = cap.Message
						} else if len(secPolicy.Spec.Capabilities.Message) > 0 {
							match.Message = secPolicy.Spec.Capabilities.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						switch cap.Capability {
						case "net_raw":
							match.Source = ""
							match.Operation = "Network"
							match.Resource = "type=SOCK_RAW protocol=1"

						default:
							continue
						}

						if len(cap.Action) > 0 {
							match.Action = cap.Action
						} else if len(secPolicy.Spec.Capabilities.Action) > 0 {
							match.Action = secPolicy.Spec.Capabilities.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range cap.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if cap.Severity > 0 {
									match.Severity = strconv.Itoa(cap.Severity)
								} else if secPolicy.Spec.Capabilities.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Capabilities.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(cap.Tags) > 0 {
									match.Tags = cap.Tags
								} else if len(secPolicy.Spec.Capabilities.Tags) > 0 {
									match.Tags = secPolicy.Spec.Capabilities.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(cap.Message) > 0 {
									match.Message = cap.Message
								} else if len(secPolicy.Spec.Capabilities.Message) > 0 {
									match.Message = secPolicy.Spec.Capabilities.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Path
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"

								default:
									continue
								}

								if len(cap.Action) > 0 {
									match.Action = cap.Action
								} else if len(secPolicy.Spec.Capabilities.Action) > 0 {
									match.Action = secPolicy.Spec.Capabilities.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if cap.Severity > 0 {
									match.Severity = strconv.Itoa(cap.Severity)
								} else if secPolicy.Spec.Capabilities.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Capabilities.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(cap.Tags) > 0 {
									match.Tags = cap.Tags
								} else if len(secPolicy.Spec.Capabilities.Tags) > 0 {
									match.Tags = secPolicy.Spec.Capabilities.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(cap.Message) > 0 {
									match.Message = cap.Message
								} else if len(secPolicy.Spec.Capabilities.Message) > 0 {
									match.Message = secPolicy.Spec.Capabilities.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Directory
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"

								default:
									continue
								}

								if len(cap.Action) > 0 {
									match.Action = cap.Action
								} else if len(secPolicy.Spec.Capabilities.Action) > 0 {
									match.Action = secPolicy.Spec.Capabilities.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
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
		delete(fd.SecurityPolicies, fd.HostName)
	} else { // ADDED | MODIFIED
		matches := tp.MatchPolicies{}

		for _, secPolicy := range secPolicies {
			if len(secPolicy.Spec.Process.MatchPaths) > 0 {
				for _, path := range secPolicy.Spec.Process.MatchPaths {
					if len(path.FromSource) == 0 {
						match := tp.MatchPolicy{}

						match.PolicyName = secPolicy.Metadata["policyName"]

						if path.Severity > 0 {
							match.Severity = strconv.Itoa(path.Severity)
						} else if secPolicy.Spec.Process.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(path.Tags) > 0 {
							match.Tags = path.Tags
						} else if len(secPolicy.Spec.Process.Tags) > 0 {
							match.Tags = secPolicy.Spec.Process.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(path.Message) > 0 {
							match.Message = path.Message
						} else if len(secPolicy.Spec.Process.Message) > 0 {
							match.Message = secPolicy.Spec.Process.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						match.Source = ""
						match.Operation = "Process"
						match.Resource = path.Path

						if len(path.Action) > 0 {
							match.Action = path.Action
						} else if len(secPolicy.Spec.Process.Action) > 0 {
							match.Action = secPolicy.Spec.Process.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if path.Severity > 0 {
									match.Severity = strconv.Itoa(path.Severity)
								} else if secPolicy.Spec.Process.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(path.Tags) > 0 {
									match.Tags = path.Tags
								} else if len(secPolicy.Spec.Process.Tags) > 0 {
									match.Tags = secPolicy.Spec.Process.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(path.Message) > 0 {
									match.Message = path.Message
								} else if len(secPolicy.Spec.Process.Message) > 0 {
									match.Message = secPolicy.Spec.Process.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = path.Path

								if len(path.Action) > 0 {
									match.Action = path.Action
								} else if len(secPolicy.Spec.Process.Action) > 0 {
									match.Action = secPolicy.Spec.Process.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if path.Severity > 0 {
									match.Severity = strconv.Itoa(path.Severity)
								} else if secPolicy.Spec.Process.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(path.Tags) > 0 {
									match.Tags = path.Tags
								} else if len(secPolicy.Spec.Process.Tags) > 0 {
									match.Tags = secPolicy.Spec.Process.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(path.Message) > 0 {
									match.Message = path.Message
								} else if len(secPolicy.Spec.Process.Message) > 0 {
									match.Message = secPolicy.Spec.Process.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = path.Path

								if len(path.Action) > 0 {
									match.Action = path.Action
								} else if len(secPolicy.Spec.Process.Action) > 0 {
									match.Action = secPolicy.Spec.Process.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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

						if dir.Severity > 0 {
							match.Severity = strconv.Itoa(dir.Severity)
						} else if secPolicy.Spec.Process.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(dir.Tags) > 0 {
							match.Tags = dir.Tags
						} else if len(secPolicy.Spec.Process.Tags) > 0 {
							match.Tags = secPolicy.Spec.Process.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(dir.Message) > 0 {
							match.Message = dir.Message
						} else if len(secPolicy.Spec.Process.Message) > 0 {
							match.Message = secPolicy.Spec.Process.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						match.Source = ""
						match.Operation = "Process"
						match.Resource = dir.Directory

						if len(dir.Action) > 0 {
							match.Action = dir.Action
						} else if len(secPolicy.Spec.Process.Action) > 0 {
							match.Action = secPolicy.Spec.Process.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if dir.Severity > 0 {
									match.Severity = strconv.Itoa(dir.Severity)
								} else if secPolicy.Spec.Process.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(dir.Tags) > 0 {
									match.Tags = dir.Tags
								} else if len(secPolicy.Spec.Process.Tags) > 0 {
									match.Tags = secPolicy.Spec.Process.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(dir.Message) > 0 {
									match.Message = dir.Message
								} else if len(secPolicy.Spec.Process.Message) > 0 {
									match.Message = secPolicy.Spec.Process.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Path
								match.Operation = "Process"
								match.Resource = dir.Directory

								if len(dir.Action) > 0 {
									match.Action = dir.Action
								} else if len(secPolicy.Spec.Process.Action) > 0 {
									match.Action = secPolicy.Spec.Process.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if dir.Severity > 0 {
									match.Severity = strconv.Itoa(dir.Severity)
								} else if secPolicy.Spec.Process.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Process.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(dir.Tags) > 0 {
									match.Tags = dir.Tags
								} else if len(secPolicy.Spec.Process.Tags) > 0 {
									match.Tags = secPolicy.Spec.Process.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(dir.Message) > 0 {
									match.Message = dir.Message
								} else if len(secPolicy.Spec.Process.Message) > 0 {
									match.Message = secPolicy.Spec.Process.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Directory
								match.Operation = "Process"
								match.Resource = dir.Directory

								if len(dir.Action) > 0 {
									match.Action = dir.Action
								} else if len(secPolicy.Spec.Process.Action) > 0 {
									match.Action = secPolicy.Spec.Process.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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

						if path.Severity > 0 {
							match.Severity = strconv.Itoa(path.Severity)
						} else if secPolicy.Spec.File.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(path.Tags) > 0 {
							match.Tags = path.Tags
						} else if len(secPolicy.Spec.File.Tags) > 0 {
							match.Tags = secPolicy.Spec.File.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(path.Message) > 0 {
							match.Message = path.Message
						} else if len(secPolicy.Spec.File.Message) > 0 {
							match.Message = secPolicy.Spec.File.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						match.Source = ""
						match.Operation = "File"
						match.Resource = path.Path

						if len(path.Action) > 0 {
							match.Action = path.Action
						} else if len(secPolicy.Spec.File.Action) > 0 {
							match.Action = secPolicy.Spec.File.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range path.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if path.Severity > 0 {
									match.Severity = strconv.Itoa(path.Severity)
								} else if secPolicy.Spec.File.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(path.Tags) > 0 {
									match.Tags = path.Tags
								} else if len(secPolicy.Spec.File.Tags) > 0 {
									match.Tags = secPolicy.Spec.File.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(path.Message) > 0 {
									match.Message = path.Message
								} else if len(secPolicy.Spec.File.Message) > 0 {
									match.Message = secPolicy.Spec.File.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = path.Path

								if len(path.Action) > 0 {
									match.Action = path.Action
								} else if len(secPolicy.Spec.File.Action) > 0 {
									match.Action = secPolicy.Spec.File.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if path.Severity > 0 {
									match.Severity = strconv.Itoa(path.Severity)
								} else if secPolicy.Spec.File.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(path.Tags) > 0 {
									match.Tags = path.Tags
								} else if len(secPolicy.Spec.File.Tags) > 0 {
									match.Tags = secPolicy.Spec.File.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(path.Message) > 0 {
									match.Message = path.Message
								} else if len(secPolicy.Spec.File.Message) > 0 {
									match.Message = secPolicy.Spec.File.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = path.Path

								if len(path.Action) > 0 {
									match.Action = path.Action
								} else if len(secPolicy.Spec.File.Action) > 0 {
									match.Action = secPolicy.Spec.File.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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

						if dir.Severity > 0 {
							match.Severity = strconv.Itoa(dir.Severity)
						} else if secPolicy.Spec.File.Severity > 0 {
							match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
						} else {
							match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
						}

						if len(dir.Tags) > 0 {
							match.Tags = dir.Tags
						} else if len(secPolicy.Spec.File.Tags) > 0 {
							match.Tags = secPolicy.Spec.File.Tags
						} else {
							match.Tags = secPolicy.Spec.Tags
						}

						if len(dir.Message) > 0 {
							match.Message = dir.Message
						} else if len(secPolicy.Spec.File.Message) > 0 {
							match.Message = secPolicy.Spec.File.Message
						} else {
							match.Message = secPolicy.Spec.Message
						}

						match.Source = ""
						match.Operation = "File"
						match.Resource = dir.Directory

						if len(dir.Action) > 0 {
							match.Action = dir.Action
						} else if len(secPolicy.Spec.File.Action) > 0 {
							match.Action = secPolicy.Spec.File.Action
						} else {
							match.Action = secPolicy.Spec.Action
						}

						matches.Policies = append(matches.Policies, match)
					} else {
						for _, src := range dir.FromSource {
							if len(src.Path) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if dir.Severity > 0 {
									match.Severity = strconv.Itoa(dir.Severity)
								} else if secPolicy.Spec.File.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(dir.Tags) > 0 {
									match.Tags = dir.Tags
								} else if len(secPolicy.Spec.File.Tags) > 0 {
									match.Tags = secPolicy.Spec.File.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(dir.Message) > 0 {
									match.Message = dir.Message
								} else if len(secPolicy.Spec.File.Message) > 0 {
									match.Message = secPolicy.Spec.File.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Path
								match.Operation = "File"
								match.Resource = dir.Directory

								if len(dir.Action) > 0 {
									match.Action = dir.Action
								} else if len(secPolicy.Spec.File.Action) > 0 {
									match.Action = secPolicy.Spec.File.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if dir.Severity > 0 {
									match.Severity = strconv.Itoa(dir.Severity)
								} else if secPolicy.Spec.File.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.File.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(dir.Tags) > 0 {
									match.Tags = dir.Tags
								} else if len(secPolicy.Spec.File.Tags) > 0 {
									match.Tags = secPolicy.Spec.File.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(dir.Message) > 0 {
									match.Message = dir.Message
								} else if len(secPolicy.Spec.File.Message) > 0 {
									match.Message = secPolicy.Spec.File.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								match.Source = src.Directory
								match.Operation = "File"
								match.Resource = dir.Directory

								if len(dir.Action) > 0 {
									match.Action = dir.Action
								} else if len(secPolicy.Spec.File.Action) > 0 {
									match.Action = secPolicy.Spec.File.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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

								if proto.Severity > 0 {
									match.Severity = strconv.Itoa(proto.Severity)
								} else if secPolicy.Spec.Network.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Network.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(proto.Tags) > 0 {
									match.Tags = proto.Tags
								} else if len(secPolicy.Spec.Network.Tags) > 0 {
									match.Tags = secPolicy.Spec.Network.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(proto.Message) > 0 {
									match.Message = proto.Message
								} else if len(secPolicy.Spec.Network.Message) > 0 {
									match.Message = secPolicy.Spec.Network.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

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

								if len(proto.Action) > 0 {
									match.Action = proto.Action
								} else if len(secPolicy.Spec.Network.Action) > 0 {
									match.Action = secPolicy.Spec.Network.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if proto.Severity > 0 {
									match.Severity = strconv.Itoa(proto.Severity)
								} else if secPolicy.Spec.Network.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Network.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(proto.Tags) > 0 {
									match.Tags = proto.Tags
								} else if len(secPolicy.Spec.Network.Tags) > 0 {
									match.Tags = secPolicy.Spec.Network.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(proto.Message) > 0 {
									match.Message = proto.Message
								} else if len(secPolicy.Spec.Network.Message) > 0 {
									match.Message = secPolicy.Spec.Network.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

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

								if len(proto.Action) > 0 {
									match.Action = proto.Action
								} else if len(secPolicy.Spec.Network.Action) > 0 {
									match.Action = secPolicy.Spec.Network.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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

								if cap.Severity > 0 {
									match.Severity = strconv.Itoa(cap.Severity)
								} else if secPolicy.Spec.Capabilities.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Capabilities.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(cap.Tags) > 0 {
									match.Tags = cap.Tags
								} else if len(secPolicy.Spec.Capabilities.Tags) > 0 {
									match.Tags = secPolicy.Spec.Capabilities.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(cap.Message) > 0 {
									match.Message = cap.Message
								} else if len(secPolicy.Spec.Capabilities.Message) > 0 {
									match.Message = secPolicy.Spec.Capabilities.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Path
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"

								default:
									continue
								}

								if len(cap.Action) > 0 {
									match.Action = cap.Action
								} else if len(secPolicy.Spec.Capabilities.Action) > 0 {
									match.Action = secPolicy.Spec.Capabilities.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

								matches.Policies = append(matches.Policies, match)
							} else if len(src.Directory) > 0 {
								match := tp.MatchPolicy{}

								match.PolicyName = secPolicy.Metadata["policyName"]

								if cap.Severity > 0 {
									match.Severity = strconv.Itoa(cap.Severity)
								} else if secPolicy.Spec.Capabilities.Severity > 0 {
									match.Severity = strconv.Itoa(secPolicy.Spec.Capabilities.Severity)
								} else {
									match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
								}

								if len(cap.Tags) > 0 {
									match.Tags = cap.Tags
								} else if len(secPolicy.Spec.Capabilities.Tags) > 0 {
									match.Tags = secPolicy.Spec.Capabilities.Tags
								} else {
									match.Tags = secPolicy.Spec.Tags
								}

								if len(cap.Message) > 0 {
									match.Message = cap.Message
								} else if len(secPolicy.Spec.Capabilities.Message) > 0 {
									match.Message = secPolicy.Spec.Capabilities.Message
								} else {
									match.Message = secPolicy.Spec.Message
								}

								switch cap.Capability {
								case "net_raw":
									match.Source = src.Directory
									match.Operation = "Network"
									match.Resource = "type=SOCK_RAW protocol=1"

								default:
									continue
								}

								if len(cap.Action) > 0 {
									match.Action = cap.Action
								} else if len(secPolicy.Spec.Capabilities.Action) > 0 {
									match.Action = secPolicy.Spec.Capabilities.Action
								} else {
									match.Action = secPolicy.Spec.Action
								}

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

	if log.Result == "Passed" || log.Result == "Operation not permitted" || log.Result == "Permission denied" {
		fd.SecurityPoliciesLock.RLock()

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

				// if fd.EnableSystemLog {
				// 	// Failed operations
				// 	log.Type = "HostLog"
				// 	return log
				// }
			} else {
				if log.Action == "Allow" {
					// use 'AllowWithAudit' to get the logs for allowed operations
					return tp.Log{}
				}

				// if fd.EnableSystemLog {
				// 	// Passed operations
				// 	log.Type = "HostLog"
				// 	return log
				// }
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
