// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package networkpolicyenforcer

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"go.aporeto.io/netlink-go/nflog"
)

// ============================= //
// == Network Policy Enforcer == //
// ============================= //

// NetworkRule Structure
type NetworkRule struct { // represents a single nftables rule entry
	TableFamily string // ip or ip6
	Chain       string // INPUT or OUTPUT
	RuleContent string
}

// NetworkPolicyEnforcer Structure
type NetworkPolicyEnforcer struct {
	// logs
	Logger *fd.Feeder

	// rules
	Rules     []NetworkRule
	RulesLock *sync.RWMutex

	// nflog handle to close it on destroy
	nflogHandle nflog.NFLog

	// Rate Limiting Cache
	// Key: string (Flow Hash), Value: time.Time (Last Seen)
	LogCache sync.Map
}

// NewNetworkPolicyEnforcer Function
func NewNetworkPolicyEnforcer(logger *fd.Feeder) *NetworkPolicyEnforcer {

	ne := &NetworkPolicyEnforcer{}

	ne.Logger = logger

	ne.Rules = []NetworkRule{}
	ne.RulesLock = &sync.RWMutex{}

	// Start Cache Cleanup Routine (runs every 1 minute)
	go func() {
		for range time.Tick(1 * time.Minute) {
			now := time.Now()
			ne.LogCache.Range(func(key, value interface{}) bool {
				lastSeen := value.(time.Time)
				// If log is older than 1 minute, delete it from cache
				if now.Sub(lastSeen) > 1*time.Minute {
					ne.LogCache.Delete(key)
				}
				return true
			})
		}
	}()

	// monitor logged packets
	go ne.monitorLoggedPackets()

	return ne
}

func getProtocolName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	case 132:
		return "SCTP"
	default:
		// Fallback for less common protocols (e.g., Proto-132)
		return fmt.Sprintf("Proto-%d", p)
	}
}

// monitorLoggedPackets Function
func (ne *NetworkPolicyEnforcer) monitorLoggedPackets() {
	callback := func(pkt *nflog.NfPacket, data interface{}) {

		// 1. Create a Unique Key for this Flow
		// We use SrcIP, SrcPort, DstIP, DstPort, Protocol, and the Policy Name
		// This ensures we silence retransmissions of the SAME connection,
		// but we still alert if a NEW connection tries (different SrcPort).
		flowKey := fmt.Sprintf("%s:%d->%s:%d/%d-%s",
			pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Protocol, pkt.Prefix)

		// 2. Check Rate Limit (Throttle: 5 Seconds)
		// If we saw this exact packet in the last 5 seconds, ignore it.
		if lastSeen, loaded := ne.LogCache.Load(flowKey); loaded {
			if time.Since(lastSeen.(time.Time)) < 10*time.Second {
				return // SKIP LOGGING
			}
		}

		// 3. Update Timestamp
		ne.LogCache.Store(flowKey, time.Now())

		log := tp.Log{}

		timestamp, updatedTime := kl.GetDateTimeNow()

		log.Timestamp = timestamp
		log.UpdatedTime = updatedTime

		log.Operation = "NetworkFirewall"

		log.Resource = pkt.Prefix
		log.Data = fmt.Sprintf("SourceIP=%s SourcePort=%d DestinationIP=%s DestinationPort=%d Protocol=%s", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, getProtocolName(pkt.Protocol))

		parts := strings.Split(pkt.Prefix, " ")
		action := parts[2]
		log.Action = action
		if action != "Block" {
			log.Result = "Passed"
		} else {
			log.Result = "Permission denied"
		}

		log.Enforcer = "NetworkPolicyEnforcer"

		ne.Logger.PushLog(log)
	}

	errorCallback := func(err error) {
		ne.Logger.Err(err.Error())
	}

	if _, err := nflog.BindAndListenForLogs([]uint16{0}, 64, callback, errorCallback); err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("Failed to bind NFLOG: %v", err)
		}
	}
}

// UpdateHostSecurityPolicies Function
func (ne *NetworkPolicyEnforcer) UpdateNetworkSecurityPolicies(secPolicies []tp.NetworkSecurityPolicy) {
	ne.RulesLock.Lock()
	defer ne.RulesLock.Unlock()

	var newRules []NetworkRule
	hasAllowPolicy := false

	// 1. Generate Custom Rules
	for _, policy := range secPolicies {

		// check if this is an Allow policy to trigger default posture later
		if strings.EqualFold(policy.Spec.Action, "Allow") {
			hasAllowPolicy = true
		}

		policyName, _ := policy.Metadata["policyName"]

		// Ingress
		for _, ingress := range policy.Spec.Ingress {
			rules := generateRules("INPUT", ingress.From, ingress.Ports, ingress.Interface, policy.Spec.Action, policy.Spec.Message, policyName)
			newRules = append(newRules, rules...)
		}
		// Egress
		for _, egress := range policy.Spec.Egress {
			rules := generateRules("OUTPUT", egress.To, egress.Ports, egress.Interface, policy.Spec.Action, policy.Spec.Message, policyName)
			newRules = append(newRules, rules...)
		}
	}

	// 2. Add Default Posture Rule (Catch-All) if an Allow policy exists
	if hasAllowPolicy {
		defaultAction := "drop"
		actionKeyword := "Block"
		policyName := "Default" // Base name for the policy

		// Adjust based on configuration
		if cfg.GlobalCfg.HostDefaultNetworkPosture == "audit" {
			defaultAction = "accept"
			actionKeyword = "Audit"
		}

		// Create specific rules for INPUT and OUTPUT to include the chain name in the log prefix
		// Format: "PolicyName Chain Action" -> "Default-Block INPUT Block"

		// INPUT Rule
		inputPrefix := fmt.Sprintf("%s INPUT %s", policyName, actionKeyword)
		inputRule := fmt.Sprintf("log prefix %q group 0 %s", inputPrefix, defaultAction)

		// OUTPUT Rule
		outputPrefix := fmt.Sprintf("%s OUTPUT %s", policyName, actionKeyword)
		outputRule := fmt.Sprintf("log prefix %q group 0 %s", outputPrefix, defaultAction)

		// Append rules specifically for their chains
		newRules = append(newRules,
			NetworkRule{TableFamily: "ip", Chain: "INPUT", RuleContent: inputRule},
			NetworkRule{TableFamily: "ip", Chain: "OUTPUT", RuleContent: outputRule},
			NetworkRule{TableFamily: "ip6", Chain: "INPUT", RuleContent: inputRule},
			NetworkRule{TableFamily: "ip6", Chain: "OUTPUT", RuleContent: outputRule},
		)
	}

	ne.Rules = newRules

	// 3. Apply
	if err := ne.applyNFTables(hasAllowPolicy); err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("Failed to apply network policies: %v", err)
		}
	}
}

func generateRules(chain string, peers []tp.NetworkPeer, ports []tp.PortType, ifaces []string, action, message, policyName string) []NetworkRule {
	var rules []NetworkRule

	// Action Map
	// Allow -> accept (no log)
	// Block -> log + drop
	// Audit -> log + accept

	nftAction := "drop"
	shouldLog := true

	act := strings.ToLower(action)
	switch act {
	case "allow":
		nftAction = "accept"
		shouldLog = false // Typically Allow is silent unless configured otherwise
	case "audit":
		nftAction = "accept"
		shouldLog = true
	default:
		// Block
		nftAction = "drop"
		shouldLog = true
	}

	logPrefix := policyName + " " + chain + " " + action // x + 1 + 5 + 1 + 5 = 25; x = 13
	if message != "" {
		logPrefix = strings.ReplaceAll(message, "\"", "") // Sanitize
		if len(logPrefix) > 25 {
			logPrefix = logPrefix[:25]
		}
	}

	if len(peers) == 0 {
		peers = []tp.NetworkPeer{{}}
	}
	if len(ports) == 0 {
		ports = []tp.PortType{{}}
	}
	if len(ifaces) == 0 {
		ifaces = []string{""}
	}

	for _, peer := range peers {
		for _, port := range ports {
			for _, iface := range ifaces {
				var parts []string
				family := "ip"

				// Interface
				if iface != "" {
					op := "iifname"
					if chain == "OUTPUT" {
						op = "oifname"
					}
					parts = append(parts, fmt.Sprintf("%s %q", op, iface))
				}

				// CIDR
				if peer.IPBlock != nil && peer.IPBlock.CIDR != "" {
					if strings.Contains(peer.IPBlock.CIDR, ":") {
						family = "ip6"
					}
					dir := "saddr"
					if chain == "OUTPUT" {
						dir = "daddr"
					}
					parts = append(parts, fmt.Sprintf("%s %s %s", family, dir, peer.IPBlock.CIDR))
				}

				// Port
				if port.Port != "" {
					proto := "tcp"
					if port.Protocol != "" {
						proto = strings.ToLower(port.Protocol)
					}
					parts = append(parts, fmt.Sprintf("%s dport %s", proto, resolvePort(port.Port)))
				}

				// Log & Action
				if shouldLog {
					parts = append(parts, fmt.Sprintf("log prefix %q group 0", logPrefix))
				}
				parts = append(parts, nftAction)

				rules = append(rules, NetworkRule{
					TableFamily: family,
					Chain:       chain,
					RuleContent: strings.Join(parts, " "),
				})
			}
		}
	}
	return rules
}

func (ne *NetworkPolicyEnforcer) applyNFTables(hasAllowPolicy bool) error {
	// Default to 'accept' (Allow-by-default behavior)
	chainPolicy := "accept"

	// If we have at least one Allow policy, we switch to Default Deny (Whitelist) mode.
	// However, the actual chain policy depends on the global posture (Block vs Audit).
	if hasAllowPolicy {
		if cfg.GlobalCfg.HostDefaultNetworkPosture == "audit" {
			chainPolicy = "accept"
		} else {
			// Default posture is Block, so we set the chain to Drop
			chainPolicy = "drop"
		}
	}

	const nftTemplate = `
# 1. Define Tables
add table ip kubearmor
add table ip6 kubearmor

# 2. Define Chains (ensures they exist so we can flush them)
add chain ip kubearmor INPUT { type filter hook input priority filter; policy {{.ChainPolicy}}; }
add chain ip kubearmor OUTPUT { type filter hook output priority filter; policy {{.ChainPolicy}}; }
add chain ip6 kubearmor INPUT { type filter hook input priority filter; policy {{.ChainPolicy}}; }
add chain ip6 kubearmor OUTPUT { type filter hook output priority filter; policy {{.ChainPolicy}}; }

# 3. Flush Old Rules
flush chain ip kubearmor INPUT
flush chain ip kubearmor OUTPUT
flush chain ip6 kubearmor INPUT
flush chain ip6 kubearmor OUTPUT

# 4. Add New Rules
table ip kubearmor {
	chain INPUT {
		iifname "lo" accept
        ct state established,related accept

		{{- range .IPv4Input }}
		{{ . }}
		{{- end }}
	}
	chain OUTPUT {
		oifname "lo" accept
        ct state established,related accept

		{{- range .IPv4Output }}
		{{ . }}
		{{- end }}
	}
}

table ip6 kubearmor {
	chain INPUT {
		iifname "lo" accept
        ct state established,related accept
		
		{{- range .IPv6Input }}
		{{ . }}
		{{- end }}
	}
	chain OUTPUT {
		oifname "lo" accept
        ct state established,related accept

		{{- range .IPv6Output }}
		{{ . }}
		{{- end }}
	}
}
`
	data := struct {
		ChainPolicy string
		IPv4Input   []string
		IPv4Output  []string
		IPv6Input   []string
		IPv6Output  []string
	}{
		ChainPolicy: chainPolicy,
	}

	// Sort rules into categories
	for _, rule := range ne.Rules {
		if rule.TableFamily == "ip" {
			if rule.Chain == "INPUT" {
				data.IPv4Input = append(data.IPv4Input, rule.RuleContent)
			} else {
				data.IPv4Output = append(data.IPv4Output, rule.RuleContent)
			}
		} else if rule.TableFamily == "ip6" {
			if rule.Chain == "INPUT" {
				data.IPv6Input = append(data.IPv6Input, rule.RuleContent)
			} else {
				data.IPv6Output = append(data.IPv6Output, rule.RuleContent)
			}
		}
	}

	t := template.Must(template.New("nft").Parse(nftTemplate))
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return err
	}

	// Apply using nft -f
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = &buf
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft error: %s", string(output))
	}

	return nil
}

func resolvePort(port string) string {
	if _, err := strconv.Atoi(port); err == nil {
		return port
	}
	services := map[string]string{"ssh": "22", "http": "80", "https": "443", "dns": "53"}
	if val, ok := services[strings.ToLower(port)]; ok {
		return val
	}
	return port
}

// DestroyNetworkPolicyEnforcer Function
func (ne *NetworkPolicyEnforcer) DestroyNetworkPolicyEnforcer() error {
	// skip if Network Policy Enforcer is not active
	if ne == nil {
		return nil
	}
	cleanupCmd := "delete table ip kubearmor; delete table ip6 kubearmor"
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(cleanupCmd)
	_ = cmd.Run()
	ne = nil
	return nil
}
