package monitor

import (
	"strconv"
	"strings"

	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ======================= //
// == Security Policies == //
// ======================= //

// UpdateSecurityPolicies Function
func (mon *ContainerMonitor) UpdateSecurityPolicies(action string, conGroup tp.ContainerGroup) {
	if action == "DELETED" {
		delete(mon.SecurityPolicies, conGroup.NamespaceName+"_"+conGroup.ContainerGroupName)
	} else { // ADDED | MODIFIED
		matches := tp.MatchPolicies{}

		for _, secPolicy := range conGroup.SecurityPolicies {
			if len(secPolicy.Spec.Process.MatchPaths) > 0 {
				for _, path := range secPolicy.Spec.Process.MatchPaths {
					match := tp.MatchPolicy{}
					match.PolicyName = secPolicy.Metadata["policyName"]
					match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
					match.Operation = "Process"
					match.Resource = path.Path
					match.Action = secPolicy.Spec.Action
					matches.Policies = append(matches.Policies, match)
				}
			}

			if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
				for _, dir := range secPolicy.Spec.Process.MatchDirectories {
					match := tp.MatchPolicy{}
					match.PolicyName = secPolicy.Metadata["policyName"]
					match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
					match.Operation = "Process"
					match.Resource = dir.Directory
					match.Action = secPolicy.Spec.Action
					matches.Policies = append(matches.Policies, match)
				}
			}

			if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
				//
			}

			if len(secPolicy.Spec.File.MatchPaths) > 0 {
				for _, path := range secPolicy.Spec.File.MatchPaths {
					match := tp.MatchPolicy{}
					match.PolicyName = secPolicy.Metadata["policyName"]
					match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
					match.Operation = "File"
					match.Resource = path.Path
					match.Action = secPolicy.Spec.Action
					matches.Policies = append(matches.Policies, match)
				}
			}

			if len(secPolicy.Spec.File.MatchPatterns) > 0 {
				//
			}

			if len(secPolicy.Spec.File.MatchDirectories) > 0 {
				for _, dir := range secPolicy.Spec.File.MatchDirectories {
					match := tp.MatchPolicy{}
					match.PolicyName = secPolicy.Metadata["policyName"]
					match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
					match.Operation = "File"
					match.Resource = dir.Directory
					match.Action = secPolicy.Spec.Action
					matches.Policies = append(matches.Policies, match)
				}
			}

			if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
				for _, proto := range secPolicy.Spec.Network.MatchProtocols {
					match := tp.MatchPolicy{}
					match.PolicyName = secPolicy.Metadata["policyName"]
					match.Severity = strconv.Itoa(secPolicy.Spec.Severity)
					match.Operation = "Network"

					switch proto.Protocol {
					case "TCP", "tcp":
						match.Resource = "type=SOCK_STREAM"
					case "UDP", "udp":
						match.Resource = "type=SOCK_DGRAM"
					case "ICMP", "icmp":
						match.Resource = "type=SOCK_RAW protocol=1"
					}

					match.Action = secPolicy.Spec.Action
					matches.Policies = append(matches.Policies, match)
				}
			}

			if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
				for _, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
					match := tp.MatchPolicy{}
					match.PolicyName = secPolicy.Metadata["policyName"]
					match.Severity = strconv.Itoa(secPolicy.Spec.Severity)

					switch cap.Capability {
					case "net_raw":
						match.Operation = "Network"
						match.Resource = "type=SOCK_RAW protocol=1"
					}

					match.Action = secPolicy.Spec.Action
					matches.Policies = append(matches.Policies, match)
				}
			}

			if len(secPolicy.Spec.Resource.MatchResources) > 0 {
				//
			}
		}

		name := conGroup.NamespaceName + "_" + conGroup.ContainerGroupName

		mon.SecurityPoliciesLock.Lock()
		mon.SecurityPolicies[name] = matches
		mon.SecurityPoliciesLock.Unlock()
	}
}

// UpdateMatchedPolicy Function
func (mon *ContainerMonitor) UpdateMatchedPolicy(log tp.Log, retval int64) tp.Log {
	allowProcPolicy := ""
	allowProcPolicySeverity := ""

	allowFilePolicy := ""
	allowFilePolicySeverity := ""

	allowNetworkPolicy := ""
	allowNetworkPolicySeverity := ""

	mon.SecurityPoliciesLock.Lock()

	secPolicies := mon.SecurityPolicies[log.NamespaceName+"_"+log.PodName].Policies
	for _, secPolicy := range secPolicies {
		if secPolicy.Action == "Allow" || secPolicy.Action == "AllowWithAudit" {
			if secPolicy.Operation == "Process" {
				if allowProcPolicy == "" {
					allowProcPolicy = secPolicy.PolicyName
					allowProcPolicySeverity = secPolicy.Severity
				} else if !strings.Contains(allowProcPolicy, secPolicy.PolicyName) {
					allowProcPolicy = allowProcPolicy + "," + secPolicy.PolicyName
					allowProcPolicySeverity = allowProcPolicySeverity + "," + secPolicy.Severity
				}
			} else if secPolicy.Operation == "File" {
				if allowFilePolicy == "" {
					allowFilePolicy = secPolicy.PolicyName
					allowFilePolicySeverity = secPolicy.Severity
				} else if !strings.Contains(allowFilePolicy, secPolicy.PolicyName) {
					allowFilePolicy = allowFilePolicy + "," + secPolicy.PolicyName
					allowFilePolicySeverity = allowFilePolicySeverity + "," + secPolicy.Severity
				}
			} else if secPolicy.Operation == "Network" {
				if allowNetworkPolicy == "" {
					allowNetworkPolicy = secPolicy.PolicyName
					allowNetworkPolicySeverity = secPolicy.Severity
				} else if !strings.Contains(allowNetworkPolicy, secPolicy.PolicyName) {
					allowNetworkPolicy = allowNetworkPolicy + "," + secPolicy.PolicyName
					allowNetworkPolicySeverity = allowNetworkPolicySeverity + "," + secPolicy.Severity
				}
			}
		}

		switch log.Operation {
		case "Process", "File":
			if secPolicy.Operation == log.Operation && strings.HasPrefix(log.Resource, secPolicy.Resource) {
				log.PolicyName = secPolicy.PolicyName
				log.Severity = secPolicy.Severity
				log.Type = "PolicyMatched"
				log.Action = secPolicy.Action
				break
			}
		case "Network":
			if secPolicy.Operation == log.Operation && strings.Contains(log.Resource, secPolicy.Resource) {
				log.PolicyName = secPolicy.PolicyName
				log.Severity = secPolicy.Severity
				log.Type = "PolicyMatched"
				log.Action = secPolicy.Action
				break
			}
		}
	}

	mon.SecurityPoliciesLock.Unlock()

	if log.Action == "Allow" && log.Result == "Passed" {
		return tp.Log{}
	}

	// if log.Action == "Block" && log.Result != "Passed" {
	// 	return tp.Log{}
	// }

	if log.Type == "" && retval < 0 {
		if log.Operation == "Process" && allowProcPolicy != "" {
			log.PolicyName = allowProcPolicy
			log.Severity = allowProcPolicySeverity
			log.Type = "PolicyMatched"
			log.Action = "Allow"
		} else if log.Operation == "File" && allowFilePolicy != "" {
			log.PolicyName = allowFilePolicy
			log.Severity = allowFilePolicySeverity
			log.Type = "PolicyMatched"
			log.Action = "Allow"
		} else if log.Operation == "Network" && allowNetworkPolicy != "" {
			log.PolicyName = allowNetworkPolicy
			log.Severity = allowNetworkPolicySeverity
			log.Type = "PolicyMatched"
			log.Action = "Allow"
		} else {
			log.Type = "SystemLog"
		}
	} else if log.Type != "PolicyMatched" {
		return tp.Log{}
	}

	return log
}
