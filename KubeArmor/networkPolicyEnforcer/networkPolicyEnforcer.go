// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package networkpolicyenforcer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
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

// QuotaObj Structure
type QuotaObj struct {
	Name  string
	Limit string // pre-formatted nft quota string, e.g. "500 mbytes"
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

	// Quotas
	QuotaTimers map[string]*time.Ticker
	QuotaCancel map[string]context.CancelFunc
	PodIPs      map[string]string
	QuotasLock  *sync.Mutex

	// Endpoints cache for log contextualization
	EndPoints     map[string]tp.EndPoint
	EndPointsLock *sync.RWMutex

	// Delta Engine Cache
	ActiveRules  []NetworkRule
	ActiveQuotas []QuotaObj
	Initialized  bool

	// Quota Log Silencer
	// Key: "<podIP>-<logPrefix>", Value: struct{}{}
	// Prevents repeated alerts within the same quota window.
	QuotaSilencer sync.Map
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
	ne.QuotaTimers = make(map[string]*time.Ticker)
	ne.QuotaCancel = make(map[string]context.CancelFunc)
	ne.PodIPs = make(map[string]string)
	ne.QuotasLock = &sync.Mutex{}

	ne.EndPoints = make(map[string]tp.EndPoint)
	ne.EndPointsLock = new(sync.RWMutex)

	ne.ActiveRules = []NetworkRule{}
	ne.ActiveQuotas = []QuotaObj{}
	ne.Initialized = false

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

	ne.UpdateNetworkSecurityPolicies([]tp.NetworkSecurityPolicy{}, []tp.EndPoint{}, map[string]tp.Container{})

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
type packetInfo struct {
	srcIP    string
	dstIP    string
	srcPort  uint16
	dstPort  uint16
	protocol uint8
}

func parsePacket(payload []byte, parser4, parser6 *gopacket.DecodingLayerParser, ip4 *layers.IPv4, ip6 *layers.IPv6, tcp *layers.TCP, udp *layers.UDP, sctp *layers.SCTP) packetInfo {
	var info packetInfo
	if len(payload) < 20 {
		return info
	}

	decoded := []gopacket.LayerType{}
	version := payload[0] >> 4
	if version == 4 {
		_ = parser4.DecodeLayers(payload, &decoded)
	} else if version == 6 {
		_ = parser6.DecodeLayers(payload, &decoded)
	}

	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeIPv4:
			info.srcIP = ip4.SrcIP.String()
			info.dstIP = ip4.DstIP.String()
			info.protocol = uint8(ip4.Protocol)
		case layers.LayerTypeIPv6:
			info.srcIP = ip6.SrcIP.String()
			info.dstIP = ip6.DstIP.String()
			info.protocol = uint8(ip6.NextHeader)
		case layers.LayerTypeTCP:
			info.srcPort = uint16(tcp.SrcPort)
			info.dstPort = uint16(tcp.DstPort)
		case layers.LayerTypeUDP:
			info.srcPort = uint16(udp.SrcPort)
			info.dstPort = uint16(udp.DstPort)
		case layers.LayerTypeSCTP:
			info.srcPort = uint16(sctp.SrcPort)
			info.dstPort = uint16(sctp.DstPort)
		}
	}
	return info
}

func (ne *NetworkPolicyEnforcer) buildKubeArmorLog(info packetInfo, prefix string, parts []string) tp.Log {
	log := tp.Log{}
	timestamp, updatedTime := kl.GetDateTimeNow()

	log.Timestamp = timestamp
	log.UpdatedTime = updatedTime
	log.Operation = "NetworkFirewall"
	log.Resource = prefix

	quotaLevel := ""
	quotaLimit := ""
	if len(parts) > 3 {
		quotaLevel = parts[3]
	}
	if len(parts) > 4 {
		quotaLimit = parts[4]
	}

	if quotaLevel != "" {
		if quotaLimit != "" {
			log.Data = fmt.Sprintf("SourceIP=%s SourcePort=%d DestinationIP=%s DestinationPort=%d Protocol=%s QuotaLevel=%s QuotaLimit=%s", info.srcIP, info.srcPort, info.dstIP, info.dstPort, getProtocolName(info.protocol), quotaLevel, quotaLimit)
		} else {
			log.Data = fmt.Sprintf("SourceIP=%s SourcePort=%d DestinationIP=%s DestinationPort=%d Protocol=%s QuotaLevel=%s", info.srcIP, info.srcPort, info.dstIP, info.dstPort, getProtocolName(info.protocol), quotaLevel)
		}
	} else {
		log.Data = fmt.Sprintf("SourceIP=%s SourcePort=%d DestinationIP=%s DestinationPort=%d Protocol=%s", info.srcIP, info.srcPort, info.dstIP, info.dstPort, getProtocolName(info.protocol))
	}

	action := "Audit"
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

	policyName := ""
	if len(parts) > 0 {
		policyName = parts[0]
	}
	isNamedPolicy := policyName != "" && policyName != "Default" && policyName != "Host"

	if isNamedPolicy {
		log.Type = "MatchedPolicy"
		log.PolicyName = policyName
	} else if policyName == "Host" {
		log.Type = "MatchedHostPolicy"
	} else {
		log.Type = "SystemLog"
	}

	// Determine targetIP for pod metadata mapping
	var targetIP, direction string
	if len(parts) > 1 {
		direction = parts[1]
	}
	if direction == "Egress" || direction == "OUTPUT" {
		targetIP = info.srcIP
	} else if direction == "Ingress" || direction == "INPUT" {
		targetIP = info.dstIP
	}

	// Attach Kubernetes Pod metadata
	if targetIP != "" {
		ne.EndPointsLock.RLock()
		if ep, ok := ne.EndPoints[targetIP]; ok {
			log.NamespaceName = ep.NamespaceName
			log.PodName = ep.EndPointName

			var labelSlice []string
			for k, v := range ep.Labels {
				labelSlice = append(labelSlice, k+"="+v)
			}
			sort.Strings(labelSlice)
			log.Labels = strings.Join(labelSlice, ",")
		}
		ne.EndPointsLock.RUnlock()
	}

	return log
}

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
	var (
		ip4   layers.IPv4
		ip6   layers.IPv6
		tcp   layers.TCP
		udp   layers.UDP
		sctp  layers.SCTP
		icmp4 layers.ICMPv4
		icmp6 layers.ICMPv6
	)

	parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp, &sctp, &icmp4)
	parser6 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp, &udp, &sctp, &icmp6)

	// Ignore errors from missing layers (e.g. payload without TCP)
	parser4.IgnoreUnsupported = true
	parser6.IgnoreUnsupported = true

	// hook that is called for every received packet
	hook := func(attrs nflog.Attribute) int {
		var payload []byte
		logPrefix := ""

		if attrs.Payload != nil {
			payload = *attrs.Payload
		}
		if attrs.Prefix != nil {
			logPrefix = *attrs.Prefix
		}

		info := parsePacket(payload, parser4, parser6, &ip4, &ip6, &tcp, &udp, &sctp)
		if info.srcIP == "" && info.dstIP == "" {
			return 0
		}

		parts := strings.Split(logPrefix, " ")
		var targetIP, direction string
		if len(parts) > 1 {
			direction = parts[1]
		}
		if direction == "Egress" || direction == "OUTPUT" {
			targetIP = info.srcIP
		} else if direction == "Ingress" || direction == "INPUT" {
			targetIP = info.dstIP
		}

		// Quota Log Silencer:
		// For policy drops, emit ONE alert per quota window per pod+policy.
		// The key is stable (podIP + prefix), ignoring ephemeral ports.
		policyName := ""
		if len(parts) > 0 {
			policyName = parts[0]
		}
		isNamedPolicy := policyName != "" && policyName != "Default" && policyName != "Host"

		if isNamedPolicy {
			silencerKey := fmt.Sprintf("%s-%s", targetIP, logPrefix)
			if _, silenced := ne.QuotaSilencer.Load(silencerKey); silenced {
				return 0 // Already alerted for this quota window — drop silently
			}
			ne.QuotaSilencer.Store(silencerKey, struct{}{})
		} else {
			// For host/default rules, keep the 10-second flow rate limiter
			flowKey := fmt.Sprintf("%s:%d->%s:%d/%d-%s", info.srcIP, info.srcPort, info.dstIP, info.dstPort, info.protocol, logPrefix)
			if lastSeen, loaded := ne.LogCache.Load(flowKey); loaded {
				if time.Since(lastSeen.(time.Time)) < 10*time.Second {
					return 0
				}
			}
			ne.LogCache.Store(flowKey, time.Now())
		}

		log := ne.buildKubeArmorLog(info, logPrefix, parts)
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

// UpdateNetworkSecurityPolicies Function
func (ne *NetworkPolicyEnforcer) UpdateNetworkSecurityPolicies(secPolicies []tp.NetworkSecurityPolicy, endpoints []tp.EndPoint, containers map[string]tp.Container) {

	ne.EndPointsLock.Lock()
	ne.EndPoints = make(map[string]tp.EndPoint)
	for _, ep := range endpoints {
		if ep.PodIP != "" {
			ne.EndPoints[ep.PodIP] = ep
		}
	}
	ne.EndPointsLock.Unlock()

	ne.RulesLock.Lock()
	defer ne.RulesLock.Unlock()

	// Clean up existing timers
	ne.QuotasLock.Lock()
	for _, cancel := range ne.QuotaCancel {
		cancel()
	}
	ne.QuotaTimers = make(map[string]*time.Ticker)
	ne.QuotaCancel = make(map[string]context.CancelFunc)
	ne.QuotasLock.Unlock()

	var newRules []NetworkRule
	var allQuotas []QuotaObj
	hasAllowPolicy := false

	// generate Rules
	for _, policy := range secPolicies {

		if strings.EqualFold(policy.Spec.Action, "Allow") {
			hasAllowPolicy = true
		}

		policyName, _ := policy.Metadata["policyName"]

		policyLevel := "pod"
		if strings.EqualFold(policy.Spec.Level, "policy") {
			policyLevel = "policy"
		}

		var podIPs []string
		isPodPolicy := len(policy.Spec.Selector.Identities) > 0
		if isPodPolicy {
			// Find matching endpoints and collect their pod IPs
			for _, ep := range endpoints {
				matched := kl.MatchIdentities(policy.Spec.Selector.Identities, ep.Identities)
				fmt.Printf("  Endpoint %s: matched=%v, ep.PodIP=%q\n", ep.EndPointName, matched, ep.PodIP)
				if matched {
					if ep.PodIP != "" {
						podIPs = append(podIPs, ep.PodIP)
					}
				}
			}
		}
		fmt.Println("Matched Pod IPs for policy", policyName, ":", podIPs)

		// Ingress
		for idx, ingress := range policy.Spec.Ingress {
			action := policy.Spec.Action
			if action == "" {
				action = "Block" // default action, if not specified in policy
			}

			if ingress.Action != "" {
				action = ingress.Action
			}
			rules := generateRules("Ingress", ingress.From, ingress.Ports, ingress.Interface, action, policyName, ingress.Limit, ingress.Duration, idx, &allQuotas, podIPs, isPodPolicy, policyLevel)
			newRules = append(newRules, rules...)

			if ingress.Limit != "" && ingress.Duration != "" {
				parsedLimit, err := parseLimitToNFT(ingress.Limit)
				if err != nil {
					ne.Logger.Errf("Policy %s ingress[%d] has invalid limit %q: %v", policyName, idx, ingress.Limit, err)
				} else {
					parsedDuration, err := parseDurationToSeconds(ingress.Duration)
					if err != nil {
						ne.Logger.Errf("Policy %s ingress[%d] has invalid duration %q: %v", policyName, idx, ingress.Duration, err)
					} else if parsedDuration > 0 {
						_ = parsedLimit // quota already registered inside generateRules
						if isPodPolicy && len(podIPs) > 0 && policyLevel != "policy" {
							for _, ip := range podIPs {
								quotaName := sanitizeQuotaName(fmt.Sprintf("quota_%s_Ingress_%d_%s", policyName, idx, ip))
								ne.setupQuotaTimer(quotaName, parsedDuration)
							}
						} else {
							quotaName := sanitizeQuotaName(fmt.Sprintf("quota_%s_Ingress_%d", policyName, idx))
							ne.setupQuotaTimer(quotaName, parsedDuration)
						}
					}
				}
			}
		}
		// Egress
		for idx, egress := range policy.Spec.Egress {
			action := policy.Spec.Action
			if action == "" {
				action = "Block" // default action, if not specified in policy
			}

			if egress.Action != "" {
				action = egress.Action
			}
			rules := generateRules("Egress", egress.To, egress.Ports, egress.Interface, action, policyName, egress.Limit, egress.Duration, idx, &allQuotas, podIPs, isPodPolicy, policyLevel)
			newRules = append(newRules, rules...)

			if egress.Limit != "" && egress.Duration != "" {
				parsedLimit, err := parseLimitToNFT(egress.Limit)
				if err != nil {
					ne.Logger.Errf("Policy %s egress[%d] has invalid limit %q: %v", policyName, idx, egress.Limit, err)
				} else {
					parsedDuration, err := parseDurationToSeconds(egress.Duration)
					if err != nil {
						ne.Logger.Errf("Policy %s egress[%d] has invalid duration %q: %v", policyName, idx, egress.Duration, err)
					} else if parsedDuration > 0 {
						_ = parsedLimit // quota already registered inside generateRules
						if isPodPolicy && len(podIPs) > 0 && policyLevel != "policy" {
							for _, ip := range podIPs {
								quotaName := sanitizeQuotaName(fmt.Sprintf("quota_%s_Egress_%d_%s", policyName, idx, ip))
								ne.setupQuotaTimer(quotaName, parsedDuration)
							}
						} else {
							quotaName := sanitizeQuotaName(fmt.Sprintf("quota_%s_Egress_%d", policyName, idx))
							ne.setupQuotaTimer(quotaName, parsedDuration)
						}
					}
				}
			}
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

	if err := ne.applyNFTables(hasAllowPolicy, allQuotas); err != nil {
		ne.Logger.Errf("Failed to apply network policies: %v", err)
	}
}

func parseLimitToNFT(limit string) (string, error) {
	if limit == "" {
		return "", fmt.Errorf("empty limit")
	}
	limit = strings.TrimSpace(limit)

	// Split numeric prefix from unit suffix
	i := 0
	for i < len(limit) && (limit[i] >= '0' && limit[i] <= '9') {
		i++
	}
	if i == 0 {
		return "", fmt.Errorf("invalid limit %q: no numeric prefix", limit)
	}

	value, err := strconv.ParseUint(limit[:i], 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid limit value %q: %v", limit[:i], err)
	}

	unit := strings.ToUpper(strings.TrimSpace(limit[i:]))

	var bytes uint64
	switch unit {
	case "KB", "K":
		bytes = value * 1024
	case "MB", "M":
		bytes = value * 1024 * 1024
	case "GB", "G", "":
		// default to GB if no unit given
		bytes = value * 1024 * 1024 * 1024
	default:
		return "", fmt.Errorf("invalid limit unit %q: expected KB, MB, or GB", unit)
	}

	return fmt.Sprintf("%d bytes", bytes), nil
}

func parseDurationToSeconds(d string) (uint32, error) {
	if d == "" {
		return 0, nil
	}
	parsed, err := time.ParseDuration(d)
	if err != nil {
		return 0, err
	}
	return uint32(parsed.Seconds()), nil
}

// sanitizeQuotaName replaces characters that are invalid in nftables quota
// object names (hyphens, spaces, dots, colons) with underscores.
func sanitizeQuotaName(name string) string {
	r := strings.NewReplacer("-", "_", " ", "_", ".", "_", ":", "_")
	return r.Replace(name)
}

func generateRules(direction string, peers []tp.NetworkPeer, ports []tp.PortType, ifaces []string, action, policyName string, limit string, duration string, ruleIdx int, quotas *[]QuotaObj, podIPs []string, isPodPolicy bool, policyLevel string) []NetworkRule {
	var rules []NetworkRule

	if isPodPolicy && len(podIPs) == 0 {
		return rules // Do not generate any rules if it's a pod policy but no pods are scheduled on this node
	}

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

	logPrefix := policyName + " " + direction + " " + action + " " + policyLevel
	if limit != "" {
		logPrefix = logPrefix + " " + limit
	}

	// Collect CIDRs
	var ipv4CIDRs []string
	var ipv6CIDRs []string
	for _, peer := range peers {
		if peer.IPBlock == nil || peer.IPBlock.CIDR == "" {
			continue
		}

		if strings.Contains(peer.IPBlock.CIDR, ":") {
			ipv6CIDRs = append(ipv6CIDRs, peer.IPBlock.CIDR)
		} else {
			ipv4CIDRs = append(ipv4CIDRs, peer.IPBlock.CIDR)
		}
	}

	var podIPv4s []string
	var podIPv6s []string
	for _, ip := range podIPs {
		if strings.Contains(ip, ":") {
			podIPv6s = append(podIPv6s, ip)
		} else {
			podIPv4s = append(podIPv4s, ip)
		}
	}

	// Collect interfaces
	var ifaceSet []string
	for _, iface := range ifaces {
		if iface != "" {
			ifaceSet = append(ifaceSet, fmt.Sprintf("%q", iface))
		}
	}

	// Collect ports
	protoPorts := map[string][]string{} // protocol -> ports
	for _, port := range ports {

		if port.Port == "" {
			continue
		}

		proto := "tcp"
		if port.Protocol != "" {
			proto = strings.ToLower(port.Protocol)
		}

		startPort := resolvePort(port.Port)

		finalPort := startPort
		if port.EndPort != nil {
			finalPort = fmt.Sprintf("%s-%d", startPort, *port.EndPort)
		}

		protoPorts[proto] = append(protoPorts[proto], finalPort)
	}

	buildRule := func(tableFamily, addrFamily string, cidrs []string, pods []string) {
		var chains []string
		if isPodPolicy {
			chains = []string{"FORWARD"}
		} else {
			if direction == "Ingress" {
				chains = []string{"INPUT"}
			} else {
				chains = []string{"OUTPUT"}
			}
		}

		hasQuota := false
		parsedLimitStr := ""
		if limit != "" && duration != "" {
			parsedDuration, _ := parseDurationToSeconds(duration)
			if parsedDuration > 0 {
				parsed, err := parseLimitToNFT(limit)
				if err == nil {
					hasQuota = true
					parsedLimitStr = parsed
				}
			}
		}

		// If no ports specified, build a single rule
		if len(protoPorts) == 0 {
			var parts []string

			// Interface
			if len(ifaceSet) > 0 {
				op := "iifname"
				if direction == "Egress" {
					op = "oifname"
				}

				if len(ifaceSet) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s", op, ifaceSet[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s { %s }", op, strings.Join(ifaceSet, ", ")))
				}
			}

			// CIDR (Peers) — use addrFamily prefix so it works in both ip and inet tables
			if len(cidrs) > 0 {
				dir := "saddr"
				if direction == "Egress" {
					dir = "daddr"
				}

				if len(cidrs) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s %s", addrFamily, dir, cidrs[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(cidrs, ", ")))
				}
			}

			// Pods — use addrFamily prefix
			if len(pods) > 0 {
				dir := "daddr"
				if direction == "Egress" {
					dir = "saddr"
				}

				if len(pods) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s %s", addrFamily, dir, pods[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(pods, ", ")))
				}
			}

			if hasQuota {
				if isPodPolicy && len(pods) > 0 {
					var sharedQuotaName string
					if policyLevel == "policy" {
						sharedQuotaName = sanitizeQuotaName(fmt.Sprintf("quota_%s_%s_%d", policyName, direction, ruleIdx))
						*quotas = append(*quotas, QuotaObj{Name: sharedQuotaName, Limit: parsedLimitStr})
					}

					for _, pod := range pods {
						var quotaName string
						if policyLevel == "policy" {
							quotaName = sharedQuotaName
						} else {
							quotaName = sanitizeQuotaName(fmt.Sprintf("quota_%s_%s_%d_%s", policyName, direction, ruleIdx, pod))
							*quotas = append(*quotas, QuotaObj{Name: quotaName, Limit: parsedLimitStr})
						}

						var podParts []string
						// Interface
						if len(ifaceSet) > 0 {
							op := "iifname"
							if direction == "Egress" {
								op = "oifname"
							}
							if len(ifaceSet) == 1 {
								podParts = append(podParts, fmt.Sprintf("%s %s", op, ifaceSet[0]))
							} else {
								podParts = append(podParts, fmt.Sprintf("%s { %s }", op, strings.Join(ifaceSet, ", ")))
							}
						}

						// CIDR
						if len(cidrs) > 0 {
							dir := "saddr"
							if direction == "Egress" {
								dir = "daddr"
							}
							if len(cidrs) == 1 {
								podParts = append(podParts, fmt.Sprintf("%s %s %s", addrFamily, dir, cidrs[0]))
							} else {
								podParts = append(podParts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(cidrs, ", ")))
							}
						}

						// This specific pod
						dir := "daddr"
						if direction == "Egress" {
							dir = "saddr"
						}
						podParts = append(podParts, fmt.Sprintf("%s %s %s", addrFamily, dir, pod))

						overParts := append([]string(nil), podParts...)
						overParts = append(overParts, fmt.Sprintf("quota name %q", quotaName))
						if shouldLog {
							overParts = append(overParts, fmt.Sprintf("log prefix %q group 0", logPrefix))
						}
						overParts = append(overParts, nftAction)

						underParts := append([]string(nil), podParts...)
						underParts = append(underParts, "accept")

						for _, ch := range chains {
							rules = append(rules, NetworkRule{TableFamily: tableFamily, Chain: ch, RuleContent: strings.Join(overParts, " ")})
							rules = append(rules, NetworkRule{TableFamily: tableFamily, Chain: ch, RuleContent: strings.Join(underParts, " ")})
						}
					}
				} else {
					quotaName := sanitizeQuotaName(fmt.Sprintf("quota_%s_%s_%d", policyName, direction, ruleIdx))
					*quotas = append(*quotas, QuotaObj{Name: quotaName, Limit: parsedLimitStr})

					overParts := append([]string(nil), parts...)
					overParts = append(overParts, fmt.Sprintf("quota name %q", quotaName))
					if shouldLog {
						overParts = append(overParts, fmt.Sprintf("log prefix %q group 0", logPrefix))
					}
					overParts = append(overParts, nftAction)

					underParts := append([]string(nil), parts...)
					underParts = append(underParts, "accept")

					for _, ch := range chains {
						rules = append(rules, NetworkRule{TableFamily: tableFamily, Chain: ch, RuleContent: strings.Join(overParts, " ")})
						rules = append(rules, NetworkRule{TableFamily: tableFamily, Chain: ch, RuleContent: strings.Join(underParts, " ")})
					}
				}
			} else {
				if shouldLog {
					parts = append(parts, fmt.Sprintf("log prefix %q group 0", logPrefix))
				}
				parts = append(parts, nftAction)
				for _, ch := range chains {
					rules = append(rules, NetworkRule{
						TableFamily: tableFamily,
						Chain:       ch,
						RuleContent: strings.Join(parts, " "),
					})
				}
			}

			return
		}

		// Build rule per protocol
		for proto, ports := range protoPorts {
			var parts []string

			// Interface
			if len(ifaceSet) > 0 {
				op := "iifname"
				if direction == "Egress" {
					op = "oifname"
				}

				if len(ifaceSet) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s", op, ifaceSet[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s { %s }", op, strings.Join(ifaceSet, ", ")))
				}
			}

			// CIDR (Peers) — use addrFamily prefix so it works in both ip and inet tables
			if len(cidrs) > 0 {
				dir := "saddr"
				if direction == "Egress" {
					dir = "daddr"
				}

				if len(cidrs) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s %s", addrFamily, dir, cidrs[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(cidrs, ", ")))
				}
			}

			// Pods — use addrFamily prefix
			if len(pods) > 0 {
				dir := "daddr"
				if direction == "Egress" {
					dir = "saddr"
				}

				if len(pods) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s %s", addrFamily, dir, pods[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(pods, ", ")))
				}
			}

			// Ports
			if len(ports) == 1 {
				parts = append(parts, fmt.Sprintf("%s dport %s", proto, ports[0]))
			} else {
				parts = append(parts, fmt.Sprintf("%s dport { %s }", proto, strings.Join(ports, ", ")))
			}

			if hasQuota {
				if isPodPolicy && len(pods) > 0 {
					var sharedQuotaName string
					if policyLevel == "policy" {
						sharedQuotaName = sanitizeQuotaName(fmt.Sprintf("quota_%s_%s_%d", policyName, direction, ruleIdx))
						*quotas = append(*quotas, QuotaObj{Name: sharedQuotaName, Limit: parsedLimitStr})
					}

					for _, pod := range pods {
						var quotaName string
						if policyLevel == "policy" {
							quotaName = sharedQuotaName
						} else {
							quotaName = sanitizeQuotaName(fmt.Sprintf("quota_%s_%s_%d_%s", policyName, direction, ruleIdx, pod))
							*quotas = append(*quotas, QuotaObj{Name: quotaName, Limit: parsedLimitStr})
						}

						var podParts []string
						// Interface
						if len(ifaceSet) > 0 {
							op := "iifname"
							if direction == "Egress" {
								op = "oifname"
							}
							if len(ifaceSet) == 1 {
								podParts = append(podParts, fmt.Sprintf("%s %s", op, ifaceSet[0]))
							} else {
								podParts = append(podParts, fmt.Sprintf("%s { %s }", op, strings.Join(ifaceSet, ", ")))
							}
						}

						// CIDR
						if len(cidrs) > 0 {
							dir := "saddr"
							if direction == "Egress" {
								dir = "daddr"
							}
							if len(cidrs) == 1 {
								podParts = append(podParts, fmt.Sprintf("%s %s %s", addrFamily, dir, cidrs[0]))
							} else {
								podParts = append(podParts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(cidrs, ", ")))
							}
						}

						// This specific pod
						dir := "daddr"
						if direction == "Egress" {
							dir = "saddr"
						}
						podParts = append(podParts, fmt.Sprintf("%s %s %s", addrFamily, dir, pod))

						// Ports
						if len(ports) == 1 {
							podParts = append(podParts, fmt.Sprintf("%s dport %s", proto, ports[0]))
						} else {
							podParts = append(podParts, fmt.Sprintf("%s dport { %s }", proto, strings.Join(ports, ", ")))
						}

						overParts := append([]string(nil), podParts...)
						overParts = append(overParts, fmt.Sprintf("quota name %q", quotaName))
						if shouldLog {
							overParts = append(overParts, fmt.Sprintf("log prefix %q group 0", logPrefix))
						}
						overParts = append(overParts, nftAction)

						underParts := append([]string(nil), podParts...)
						underParts = append(underParts, "accept")

						for _, ch := range chains {
							rules = append(rules, NetworkRule{TableFamily: tableFamily, Chain: ch, RuleContent: strings.Join(overParts, " ")})
							rules = append(rules, NetworkRule{TableFamily: tableFamily, Chain: ch, RuleContent: strings.Join(underParts, " ")})
						}
					}
				} else {
					quotaName := sanitizeQuotaName(fmt.Sprintf("quota_%s_%s_%d", policyName, direction, ruleIdx))
					*quotas = append(*quotas, QuotaObj{Name: quotaName, Limit: parsedLimitStr})

					overParts := append([]string(nil), parts...)
					overParts = append(overParts, fmt.Sprintf("quota name %q", quotaName))
					if shouldLog {
						overParts = append(overParts, fmt.Sprintf("log prefix %q group 0", logPrefix))
					}
					overParts = append(overParts, nftAction)

					underParts := append([]string(nil), parts...)
					underParts = append(underParts, "accept")

					for _, ch := range chains {
						rules = append(rules, NetworkRule{TableFamily: tableFamily, Chain: ch, RuleContent: strings.Join(overParts, " ")})
						rules = append(rules, NetworkRule{TableFamily: tableFamily, Chain: ch, RuleContent: strings.Join(underParts, " ")})
					}
				}
			} else {
				if shouldLog {
					parts = append(parts, fmt.Sprintf("log prefix %q group 0", logPrefix))
				}
				parts = append(parts, nftAction)
				for _, ch := range chains {
					rules = append(rules, NetworkRule{TableFamily: tableFamily, Chain: ch, RuleContent: strings.Join(parts, " ")})
				}
			}
		}
	}

	hasQuota := limit != "" && duration != ""

	if !isPodPolicy || len(podIPv4s) > 0 {
		if hasQuota || isPodPolicy {
			// Pod rules (quota or not) go to inet table
			buildRule("inet", "ip", ipv4CIDRs, podIPv4s)
		} else {
			// Host-only rules stay in ip table
			buildRule("ip", "ip", ipv4CIDRs, podIPv4s)
		}
	}

	if !isPodPolicy || len(podIPv6s) > 0 {
		if hasQuota || isPodPolicy {
			// Pod rules (quota or not) go to inet table
			buildRule("inet", "ip6", ipv6CIDRs, podIPv6s)
		} else {
			// Host-only rules stay in ip6 table
			buildRule("ip6", "ip6", ipv6CIDRs, podIPv6s)
		}
	}

	return rules
}

func (ne *NetworkPolicyEnforcer) applyNFTables(hasAllowPolicy bool, quotas []QuotaObj) error {
	chainPolicy := "accept"
	if hasAllowPolicy {
		if cfg.GlobalCfg.HostDefaultNetworkPosture == "audit" {
			chainPolicy = "accept"
		} else {
			chainPolicy = "drop"
		}
	}

	// 1. Compute Quota Delta
	var inetQuotasToAdd []QuotaObj
	var inetQuotasToDelete []QuotaObj

	newQuotasMap := make(map[string]QuotaObj)
	for _, q := range quotas {
		newQuotasMap[q.Name] = q
	}

	activeQuotasMap := make(map[string]QuotaObj)
	for _, q := range ne.ActiveQuotas {
		activeQuotasMap[q.Name] = q
	}

	for name, newQ := range newQuotasMap {
		if activeQ, exists := activeQuotasMap[name]; !exists {
			inetQuotasToAdd = append(inetQuotasToAdd, newQ)
		} else if activeQ.Limit != newQ.Limit {
			inetQuotasToDelete = append(inetQuotasToDelete, activeQ)
			inetQuotasToAdd = append(inetQuotasToAdd, newQ)
		}
	}
	for name, activeQ := range activeQuotasMap {
		if _, exists := newQuotasMap[name]; !exists {
			inetQuotasToDelete = append(inetQuotasToDelete, activeQ)
		}
	}

	// 2. We still declaratively rebuild Host and Pod rules
	var ipv4Input, ipv4Output, ipv6Input, ipv6Output, inetForward, inetInput, inetOutput []string
	for _, r := range ne.Rules {
		if r.TableFamily == "ip" {
			if r.Chain == "INPUT" {
				ipv4Input = append(ipv4Input, r.RuleContent)
			} else {
				ipv4Output = append(ipv4Output, r.RuleContent)
			}
		} else if r.TableFamily == "ip6" {
			if r.Chain == "INPUT" {
				ipv6Input = append(ipv6Input, r.RuleContent)
			} else {
				ipv6Output = append(ipv6Output, r.RuleContent)
			}
		} else if r.TableFamily == "inet" {
			if r.Chain == "FORWARD" {
				inetForward = append(inetForward, r.RuleContent)
			} else if r.Chain == "INPUT" {
				inetInput = append(inetInput, r.RuleContent)
			} else {
				inetOutput = append(inetOutput, r.RuleContent)
			}
		}
	}

	const nftTemplate = `
# 1. Ensure tables exist
add table ip kubearmor
add table ip6 kubearmor
add table inet kubearmor

{{ if not .Initialized }}
# 1a. First run: Wipe inet table to ensure a clean slate
delete table inet kubearmor
add table inet kubearmor
{{ end }}

# 2. Delete Host tables to cleanly rebuild them
delete table ip kubearmor
delete table ip6 kubearmor

# 3. Create fresh Host tables
add table ip kubearmor
add table ip6 kubearmor

# 4. Host Chains
add chain ip kubearmor INPUT { type filter hook input priority 0; policy {{.ChainPolicy}}; }
add chain ip kubearmor OUTPUT { type filter hook output priority 0; policy {{.ChainPolicy}}; }
add chain ip6 kubearmor INPUT { type filter hook input priority 0; policy {{.ChainPolicy}}; }
add chain ip6 kubearmor OUTPUT { type filter hook output priority 0; policy {{.ChainPolicy}}; }

# 5. Pod Chains (they persist, so we ensure they exist)
add chain inet kubearmor FORWARD { type filter hook forward priority 1; policy accept; }
add chain inet kubearmor INPUT { type filter hook input priority 1; policy accept; }
add chain inet kubearmor OUTPUT { type filter hook output priority 1; policy accept; }

# 6. Flush Pod Chains (Deletes all rules without deleting the table/quotas)
flush chain inet kubearmor FORWARD
flush chain inet kubearmor INPUT
flush chain inet kubearmor OUTPUT

# 7. Apply Quota Deletions (Delta)
{{- range .InetQuotasToDelete }}
delete quota inet kubearmor {{.Name}}
{{- end }}

# 8. Apply Quota Additions (Delta)
{{- range .InetQuotasToAdd }}
add quota inet kubearmor {{.Name}} { over {{.Limit}} }
{{- end }}

# 9. Rebuild Pod Rules (Declarative)
{{- range .InetForward }}
add rule inet kubearmor FORWARD {{ . }}
{{- end }}
{{- range .InetInput }}
add rule inet kubearmor INPUT {{ . }}
{{- end }}
{{- range .InetOutput }}
add rule inet kubearmor OUTPUT {{ . }}
{{- end }}

# 10. Rebuild Host Rules
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
		Initialized        bool
		ChainPolicy        string
		InetQuotasToAdd    []QuotaObj
		InetQuotasToDelete []QuotaObj
		IPv4Input          []string
		IPv4Output         []string
		IPv6Input          []string
		IPv6Output         []string
		InetForward        []string
		InetInput          []string
		InetOutput         []string
	}{
		Initialized:        ne.Initialized,
		ChainPolicy:        chainPolicy,
		InetQuotasToAdd:    inetQuotasToAdd,
		InetQuotasToDelete: inetQuotasToDelete,
		IPv4Input:          ipv4Input,
		IPv4Output:         ipv4Output,
		IPv6Input:          ipv6Input,
		IPv6Output:         ipv6Output,
		InetForward:        inetForward,
		InetInput:          inetInput,
		InetOutput:         inetOutput,
	}

	// Update Delta Engine Cache
	ne.ActiveRules = make([]NetworkRule, len(ne.Rules))
	copy(ne.ActiveRules, ne.Rules)
	ne.ActiveQuotas = make([]QuotaObj, len(quotas))
	copy(ne.ActiveQuotas, quotas)
	ne.Initialized = true

	t := template.Must(template.New("nft").Parse(nftTemplate))

	tmpFile, err := os.CreateTemp("", "ka-nft-rules-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if err := t.Execute(tmpFile, data); err != nil {
		if closeError := tmpFile.Close(); closeError != nil {
			return closeError
		}
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	// Apply using nft -f
	cmd := exec.Command("nft", "-f", tmpFile.Name()) // #nosec G204
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply error: %v\nnft apply output: %s", err, string(output))
	}

	return nil
}

func (ne *NetworkPolicyEnforcer) setupQuotaTimer(quotaName string, durationSeconds uint32) {
	if durationSeconds == 0 {
		return
	}

	ne.QuotasLock.Lock()
	defer ne.QuotasLock.Unlock()

	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118
	ne.QuotaCancel[quotaName] = cancel

	ticker := time.NewTicker(time.Duration(durationSeconds) * time.Second)
	ne.QuotaTimers[quotaName] = ticker

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Reset the kernel quota counter
				if err := exec.Command("nft", "reset", "quota", "inet", "kubearmor", quotaName).Run(); err != nil { // #nosec G204
					ne.Logger.Warnf("failed to reset nftables quota %s: %v", quotaName, err)
				}
				// Re-arm the log silencer so the user gets alerted on the NEXT breach
				ne.QuotaSilencer.Range(func(key, _ any) bool {
					keyStr := key.(string)
					parts := strings.Split(keyStr, "-")
					if len(parts) > 1 {
						policyParts := strings.Split(parts[1], " ")
						if len(policyParts) >= 2 {
							policyName := sanitizeQuotaName(policyParts[0])
							direction := policyParts[1]
							if strings.Contains(quotaName, policyName) && strings.Contains(quotaName, direction) {
								sanitizedPod := sanitizeQuotaName(parts[0])
								// If the quotaName contains the pod IP, it must match this pod
								if strings.Contains(quotaName, sanitizedPod) {
									ne.QuotaSilencer.Delete(key)
								} else {
									// If it doesn't contain any pod IP (i.e. policy-level), delete it
									// Let's check if the quotaName contains any other pod IP from active endpoints
									isPodSpecific := false
									ne.EndPointsLock.Lock()
									for ip := range ne.EndPoints {
										if strings.Contains(quotaName, sanitizeQuotaName(ip)) {
											isPodSpecific = true
											break
										}
									}
									ne.EndPointsLock.Unlock()
									if !isPodSpecific {
										ne.QuotaSilencer.Delete(key)
									}
								}
							}
						}
					}
					return true
				})
			}
		}
	}()
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

	ne.QuotasLock.Lock()
	for _, t := range ne.QuotaTimers {
		t.Stop()
	}
	for _, cancel := range ne.QuotaCancel {
		cancel()
	}
	ne.QuotasLock.Unlock()

	// nflog listener
	if ne.cancelNflog != nil {
		ne.cancelNflog()
	}

	// cleanup nftables tables
	for _, family := range []string{"ip", "ip6", "inet"} {
		cmd := exec.Command("nft", "delete", "table", family, "kubearmor") // #nosec G204
		_ = cmd.Run()                                                      // Ignore error if table doesn't exist
	}

	ne = nil
	return nil
}
