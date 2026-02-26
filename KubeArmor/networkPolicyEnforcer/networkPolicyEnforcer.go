// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package networkpolicyenforcer

import (
	"bytes"
	"context"
	"fmt"
	"os"
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

	"github.com/florianl/go-nflog/v2"
	"github.com/mdlayher/netlink"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	cancelNflog context.CancelFunc

	ticker     *time.Ticker
	tickerDone chan bool

	// Rate Limiting Cache
	// Key: string (Flow Hash), Value: time.Time (Last Seen)
	LogCache sync.Map
}

// NewNetworkPolicyEnforcer Function
func NewNetworkPolicyEnforcer(logger *fd.Feeder) (*NetworkPolicyEnforcer, error) {

	// Check if running as root (UID 0)
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("requires root privileges")
	}

	// Check if the nft command is available in the system PATH
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("nft command not found in $PATH")
	}

	ne := &NetworkPolicyEnforcer{}

	ne.Logger = logger

	ne.Rules = []NetworkRule{}
	ne.RulesLock = &sync.RWMutex{}

	ne.ticker = time.NewTicker(1 * time.Minute)
	ne.tickerDone = make(chan bool, 1)

	// Start Cache Cleanup Routine (runs every 1 minute)
	go func() {
		for {
			select {
			case <-ne.tickerDone:
				return
			case t := <-ne.ticker.C:
				ne.LogCache.Range(func(key, value interface{}) bool {
					lastSeen := value.(time.Time)
					// If log is older than 1 minute, delete it from cache
					if t.Sub(lastSeen) > 1*time.Minute {
						ne.LogCache.Delete(key)
					}
					return true
				})
			}
		}
	}()

	// monitor logged packets
	go ne.monitorLoggedPackets()

	ne.UpdateNetworkSecurityPolicies([]tp.NetworkSecurityPolicy{})

	return ne, nil
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
		// Fallback for less common protocols
		return fmt.Sprintf("Proto-%d", p)
	}
}

// monitorLoggedPackets Function
func (ne *NetworkPolicyEnforcer) monitorLoggedPackets() {

	// Configure nflog
	config := nflog.Config{
		Group:    0,
		Copymode: nflog.CopyPacket,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("could not open nflog socket: %v", err)
		}
		return
	}

	// We do not defer nf.Close() here because we want it to run in the background.
	// It will be closed when DestroyNetworkPolicyEnforcer is called.

	// Increase socket read buffer size to avoid dropped logs
	if err := nf.Con.SetReadBuffer(2 * 1024 * 1024); err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("failed to set read buffer: %v", err)
		}
	}

	// Avoid receiving ENOBUFS errors
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("failed to set netlink option: %v", err)
		}
	}

	// Setup context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	ne.cancelNflog = cancel

	// Fast decoders for gopacket
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var sctp layers.SCTP
	var icmp4 layers.ICMPv4
	var icmp6 layers.ICMPv6

	parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp, &sctp, &icmp4)
	parser6 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp, &udp, &sctp, &icmp6)

	// Ignore errors from missing layers (e.g. payload without TCP)
	parser4.IgnoreUnsupported = true
	parser6.IgnoreUnsupported = true

	// hook that is called for every received packet
	hook := func(attrs nflog.Attribute) int {
		var payload []byte
		prefix := ""

		if attrs.Payload != nil {
			payload = *attrs.Payload
		}
		if attrs.Prefix != nil {
			prefix = *attrs.Prefix
		}

		if len(payload) < 20 {
			return 0 // Too short to be a valid IP packet
		}

		var srcIP, dstIP string
		var srcPort, dstPort uint16
		var protocol uint8

		decoded := []gopacket.LayerType{}

		// Check IP version
		version := payload[0] >> 4
		if version == 4 {
			_ = parser4.DecodeLayers(payload, &decoded)
		} else if version == 6 {
			_ = parser6.DecodeLayers(payload, &decoded)
		}

		// Extract parsed data
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				srcIP = ip4.SrcIP.String()
				dstIP = ip4.DstIP.String()
				protocol = uint8(ip4.Protocol)
			case layers.LayerTypeIPv6:
				srcIP = ip6.SrcIP.String()
				dstIP = ip6.DstIP.String()
				protocol = uint8(ip6.NextHeader)
			case layers.LayerTypeTCP:
				srcPort = uint16(tcp.SrcPort)
				dstPort = uint16(tcp.DstPort)
			case layers.LayerTypeUDP:
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)
			case layers.LayerTypeSCTP:
				srcPort = uint16(sctp.SrcPort)
				dstPort = uint16(sctp.DstPort)
			}
		}

		// Rate Limiting (10 Seconds)
		flowKey := fmt.Sprintf("%s:%d->%s:%d/%d-%s", srcIP, srcPort, dstIP, dstPort, protocol, prefix)
		if lastSeen, loaded := ne.LogCache.Load(flowKey); loaded {
			if time.Since(lastSeen.(time.Time)) < 10*time.Second {
				return 0 // SKIP LOGGING
			}
		}

		ne.LogCache.Store(flowKey, time.Now())

		// Generate KubeArmor Log
		log := tp.Log{}
		timestamp, updatedTime := kl.GetDateTimeNow()

		log.Timestamp = timestamp
		log.UpdatedTime = updatedTime
		log.Operation = "NetworkFirewall"
		log.Resource = prefix
		log.Data = fmt.Sprintf("SourceIP=%s SourcePort=%d DestinationIP=%s DestinationPort=%d Protocol=%s", srcIP, srcPort, dstIP, dstPort, getProtocolName(protocol))

		parts := strings.Split(prefix, " ")
		action := "Audit" // default fallback
		if len(parts) > 2 {
			action = parts[2]
		} else if strings.Contains(prefix, "Block") {
			action = "Block"
		}

		log.Action = action
		if action != "Block" {
			log.Result = "Passed"
		} else {
			log.Result = "Permission denied"
		}

		log.Enforcer = "NetworkPolicyEnforcer"

		ne.Logger.PushLog(log)

		return 0
	}

	errFunc := func(e error) int {

		// If context is cancelled (shutdown), ignore errors and return
		if ctx.Err() != nil {
			return 0
		}

		if ne.Logger != nil {
			ne.Logger.Errf("NFLOG hook error: %v", e)
		}
		return 0
	}

	// Register and block
	if err := nf.RegisterWithErrorFunc(ctx, hook, errFunc); err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("failed to register nflog hook: %v", err)
		}
		return
	}

	<-ctx.Done()
	if err := nf.Close(); err != nil {
		ne.Logger.Errf("Failed to close nflog: %v", err)
	}
}

// UpdateHostSecurityPolicies Function
func (ne *NetworkPolicyEnforcer) UpdateNetworkSecurityPolicies(secPolicies []tp.NetworkSecurityPolicy) {
	ne.RulesLock.Lock()
	defer ne.RulesLock.Unlock()

	var newRules []NetworkRule
	hasAllowPolicy := false

	// generate Rules
	for _, policy := range secPolicies {

		if strings.EqualFold(policy.Spec.Action, "Allow") {
			hasAllowPolicy = true
		}

		policyName, _ := policy.Metadata["policyName"]

		// Ingress
		for _, ingress := range policy.Spec.Ingress {
			action := policy.Spec.Action
			if action == "" {
				action = "Block" // default action, if not specified in policy
			}

			if ingress.Action != "" {
				action = ingress.Action
			}
			rules := generateRules("INPUT", ingress.From, ingress.Ports, ingress.Interface, action, policyName)
			newRules = append(newRules, rules...)
		}
		// Egress
		for _, egress := range policy.Spec.Egress {
			action := policy.Spec.Action
			if action == "" {
				action = "Block" // default action, if not specified in policy
			}

			if egress.Action != "" {
				action = egress.Action
			}
			rules := generateRules("OUTPUT", egress.To, egress.Ports, egress.Interface, action, policyName)
			newRules = append(newRules, rules...)
		}
	}

	// host log
	defaultAction := "accept"
	actionKeyword := "Allow"
	policyName := "Host" // for host logs

	// add Default Posture Rule (Catch-All) if an Allow policy exists, else rule for Host Logs
	if hasAllowPolicy {
		defaultAction = "drop"
		actionKeyword = "Block"
		policyName = "Default" // for default posture alerts

		if cfg.GlobalCfg.HostDefaultNetworkPosture == "audit" {
			defaultAction = "accept"
			actionKeyword = "Audit"
		}
	}

	// log prefix format: "PolicyName Chain Action" (e.g., "Default INPUT Block")

	// INPUT Rule
	inputPrefix := fmt.Sprintf("%s INPUT %s", policyName, actionKeyword)
	inputRule := fmt.Sprintf("log prefix %q group 0 %s", inputPrefix, defaultAction)

	// OUTPUT Rule
	outputPrefix := fmt.Sprintf("%s OUTPUT %s", policyName, actionKeyword)
	outputRule := fmt.Sprintf("log prefix %q group 0 %s", outputPrefix, defaultAction)

	// Append rules
	newRules = append(newRules,
		NetworkRule{TableFamily: "ip", Chain: "INPUT", RuleContent: inputRule},
		NetworkRule{TableFamily: "ip", Chain: "OUTPUT", RuleContent: outputRule},
		NetworkRule{TableFamily: "ip6", Chain: "INPUT", RuleContent: inputRule},
		NetworkRule{TableFamily: "ip6", Chain: "OUTPUT", RuleContent: outputRule},
	)

	ne.Rules = newRules

	if err := ne.applyNFTables(hasAllowPolicy); err != nil {
		ne.Logger.Errf("Failed to apply network policies: %v", err)
	}
}

func generateRules(chain string, peers []tp.NetworkPeer, ports []tp.PortType, ifaces []string, action, policyName string) []NetworkRule {
	var rules []NetworkRule

	// Allow -> accept (no log)
	// Block -> log + drop
	// Audit -> log + accept

	nftAction := "drop"
	shouldLog := true

	act := strings.ToLower(action)
	switch act {
	case "allow":
		nftAction = "accept"
		shouldLog = false
	case "audit":
		nftAction = "accept"
		shouldLog = true
	default:
		// Block
		nftAction = "drop"
		shouldLog = true
	}

	logPrefix := policyName + " " + chain + " " + action

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
					proto := "tcp" // default protocol
					if port.Protocol != "" {
						proto = strings.ToLower(port.Protocol)
					}

					startPort := resolvePort(port.Port)

					// check if this is a Range or Single Port
					finalPortStr := startPort
					if port.EndPort != nil {
						// range -> start-end (e.g., "80-100")
						finalPortStr = fmt.Sprintf("%s-%d", startPort, *port.EndPort)
					}

					parts = append(parts, fmt.Sprintf("%s dport %s", proto, finalPortStr))
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
	chainPolicy := "accept"

	if hasAllowPolicy {
		if cfg.GlobalCfg.HostDefaultNetworkPosture == "audit" {
			chainPolicy = "accept"
		} else {
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
        ct state { established, related } accept

		{{- range .IPv4Input }}
		{{ . }}
		{{- end }}
	}
	chain OUTPUT {
		oifname "lo" accept
        ct state { established, related } accept

		{{- range .IPv4Output }}
		{{ . }}
		{{- end }}
	}
}

table ip6 kubearmor {
	chain INPUT {
		iifname "lo" accept
        ct state { established, related } accept
		
		{{- range .IPv6Input }}
		{{ . }}
		{{- end }}
	}
	chain OUTPUT {
		oifname "lo" accept
        ct state { established, related } accept

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
		switch rule.TableFamily {
		case "ip":
			if rule.Chain == "INPUT" {
				data.IPv4Input = append(data.IPv4Input, rule.RuleContent)
			} else {
				data.IPv4Output = append(data.IPv4Output, rule.RuleContent)
			}
		case "ip6":
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
		return fmt.Errorf("nft apply error: %v\nnft apply output: %s", err, string(output))
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

	// ticker and cache cleanup goroutine
	if ne.ticker != nil {
		ne.ticker.Stop()
	}
	select {
	case ne.tickerDone <- true:
	default:
	}

	// nflog listener
	if ne.cancelNflog != nil {
		ne.cancelNflog()
	}

	cleanupCmd := "delete table ip kubearmor; delete table ip6 kubearmor"
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(cleanupCmd)
	_ = cmd.Run()
	ne = nil
	return nil
}
