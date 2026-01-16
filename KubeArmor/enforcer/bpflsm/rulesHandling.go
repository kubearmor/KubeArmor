// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package bpflsm

import (
	"errors"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// Bit Flags for Map Rule Mask
const (
	EXEC      uint8 = 1 << 0
	WRITE     uint8 = 1 << 1
	READ      uint8 = 1 << 2
	OWNER     uint8 = 1 << 3
	DIR       uint8 = 1 << 4
	RECURSIVE uint8 = 1 << 5
	HINT      uint8 = 1 << 6
	DENY      uint8 = 1 << 7
)

// Data Index for rules
const (
	PROCESS      = 0
	FILE         = 1
	NETWORK      = 0
	CAPABILITIES = 0
)

// values for posture and retval
const (
	AuditPosture = 140
	BlockPosture = 141
)

// Map Key Identifiers for Whitelist/Posture
var (
	PROCWHITELIST = InnerKey{Path: [256]byte{101}}
	FILEWHITELIST = InnerKey{Path: [256]byte{102}}
	NETWHITELIST  = InnerKey{Path: [256]byte{103}}
	CAPWHITELIST  = InnerKey{Path: [256]byte{104}}
)

// Protocol Identifiers for Network Rules
var protocols = map[string]uint8{
	"ICMP":   1,
	"TCP":    6,
	"UDP":    17,
	"ICMPv6": 58,
	"SCTP":   132,
}

// Socket Type Identifiers for Network Rules
var netType = map[string]uint8{
	"STREAM":    1,
	"DGRAM":     2,
	"RAW":       3,
	"RDM":       4,
	"SEQPACKET": 5,
	"DCCP":      6,
	"PACKET":    10,
}

// Array Keys for Network Rule Keys
const (
	FAMILY   uint8 = 1
	TYPE     uint8 = 2
	PROTOCOL uint8 = 3
)

// Key for mapping capabilities in bpf maps
const capableKey = 200

// RuleList Structure contains all the data required to set rules for a particular container
type RuleList struct {
	ProcessRuleList      map[InnerKey][2]uint8
	FileRuleList         map[InnerKey][2]uint8
	NetworkRuleList      map[InnerKey][2]uint8
	CapabilitiesRuleList map[InnerKey][2]uint8
	ProcWhiteListPosture bool
	FileWhiteListPosture bool
	NetWhiteListPosture  bool
	CapWhiteListPosture  bool
}

// Init prepares the RuleList object
func (r *RuleList) Init() {
	r.ProcessRuleList = make(map[InnerKey][2]uint8)
	r.ProcWhiteListPosture = false

	r.FileRuleList = make(map[InnerKey][2]uint8)
	r.FileWhiteListPosture = false

	r.NetworkRuleList = make(map[InnerKey][2]uint8)
	r.NetWhiteListPosture = false

	r.CapabilitiesRuleList = make(map[InnerKey][2]uint8)
	r.CapWhiteListPosture = false
}

// UpdateContainerRules updates individual container map with new rules and resolves conflicting rules
func (be *BPFEnforcer) UpdateContainerRules(id string, securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) {

	var newrules RuleList

	newrules.Init()

	// Generate Fresh Rule Set based on Updated Security Policies
	for _, secPolicy := range securityPolicies {
		for _, path := range secPolicy.Spec.Process.MatchPaths {

			var val [2]uint8
			val[PROCESS] = val[PROCESS] | EXEC
			if path.OwnerOnly {
				val[PROCESS] = val[PROCESS] | OWNER
			}
			if len(path.FromSource) == 0 {
				var key InnerKey
				if len(path.ExecName) > 0 {
					copy(key.Path[:], []byte(path.ExecName))
				} else {
					copy(key.Path[:], []byte(path.Path))
				}
				if path.Action == "Allow" {
					newrules.ProcWhiteListPosture = true
					newrules.ProcessRuleList[key] = val
				} else if path.Action == "Block" {
					val[PROCESS] = val[PROCESS] | DENY
					newrules.ProcessRuleList[key] = val
				}
			} else {
				for _, src := range path.FromSource {
					var key InnerKey
					if len(path.ExecName) > 0 {
						copy(key.Path[:], []byte(path.ExecName))
					} else {
						copy(key.Path[:], []byte(path.Path))
					}
					copy(key.Source[:], []byte(src.Path))
					if path.Action == "Allow" {
						newrules.ProcWhiteListPosture = true
						newrules.ProcessRuleList[key] = val
					} else if path.Action == "Block" {
						val[PROCESS] = val[PROCESS] | DENY
						newrules.ProcessRuleList[key] = val
					}
				}
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			var val [2]uint8
			val[PROCESS] = val[PROCESS] | EXEC
			if dir.OwnerOnly {
				val[PROCESS] = val[PROCESS] | OWNER
			}
			if dir.Recursive {
				val[PROCESS] = val[PROCESS] | RECURSIVE
			}
			if len(dir.FromSource) == 0 {
				if dir.Action == "Allow" {
					newrules.ProcWhiteListPosture = true
					dirtoMap(PROCESS, dir.Directory, "", newrules.ProcessRuleList, val)

				} else if dir.Action == "Block" {
					val[PROCESS] = val[PROCESS] | DENY
					dirtoMap(PROCESS, dir.Directory, "", newrules.ProcessRuleList, val)
				}
			} else {
				for _, src := range dir.FromSource {
					if dir.Action == "Allow" {
						newrules.ProcWhiteListPosture = true
						dirtoMap(PROCESS, dir.Directory, src.Path, newrules.ProcessRuleList, val)

					} else if dir.Action == "Block" {
						val[PROCESS] = val[PROCESS] | DENY
						dirtoMap(PROCESS, dir.Directory, src.Path, newrules.ProcessRuleList, val)
					}
				}
			}
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			var val [2]uint8
			val[FILE] = val[FILE] | READ
			if path.OwnerOnly {
				val[FILE] = val[FILE] | OWNER
			}
			if !path.ReadOnly {
				val[FILE] = val[FILE] | WRITE
			}
			if len(path.FromSource) == 0 {
				var key InnerKey
				copy(key.Path[:], []byte(path.Path))
				if path.Action == "Allow" {
					newrules.FileWhiteListPosture = true
					newrules.FileRuleList[key] = val

				} else if path.Action == "Block" {
					val[FILE] = val[FILE] | DENY
					newrules.FileRuleList[key] = val
				}
			} else {
				for _, src := range path.FromSource {
					var key InnerKey
					copy(key.Path[:], []byte(path.Path))
					copy(key.Source[:], []byte(src.Path))
					if path.Action == "Allow" {
						newrules.FileWhiteListPosture = true
						newrules.FileRuleList[key] = val

					} else if path.Action == "Block" {
						val[FILE] = val[FILE] | DENY
						newrules.FileRuleList[key] = val
					}
				}
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			var val [2]uint8
			val[FILE] = val[FILE] | READ
			if dir.OwnerOnly {
				val[FILE] = val[FILE] | OWNER
			}
			if !dir.ReadOnly {
				val[FILE] = val[FILE] | WRITE
			}
			if dir.Recursive {
				val[FILE] = val[FILE] | RECURSIVE
			}
			if len(dir.FromSource) == 0 {
				if dir.Action == "Allow" {
					newrules.FileWhiteListPosture = true
					dirtoMap(FILE, dir.Directory, "", newrules.FileRuleList, val)

				} else if dir.Action == "Block" {
					val[FILE] = val[FILE] | DENY
					dirtoMap(FILE, dir.Directory, "", newrules.FileRuleList, val)
				}
			} else {
				for _, src := range dir.FromSource {
					if dir.Action == "Allow" {
						newrules.FileWhiteListPosture = true
						dirtoMap(FILE, dir.Directory, src.Path, newrules.FileRuleList, val)

					} else if dir.Action == "Block" {
						val[FILE] = val[FILE] | DENY
						dirtoMap(FILE, dir.Directory, src.Path, newrules.FileRuleList, val)
					}
				}
			}
		}

		// handle protocol: all|ALL rules
		handleAllNetworkRule(&secPolicy.Spec.Network.MatchProtocols)

		for _, net := range secPolicy.Spec.Network.MatchProtocols {
			var val [2]uint8
			var key = InnerKey{Path: [256]byte{}, Source: [256]byte{}}
			if val, ok := protocols[strings.ToUpper(net.Protocol)]; ok {
				key.Path[0] = PROTOCOL
				key.Path[1] = val
			} else if val, ok := netType[strings.ToUpper(net.Protocol)]; ok {
				key.Path[0] = TYPE
				key.Path[1] = val
			}

			if len(net.FromSource) == 0 {
				if net.Action == "Allow" {
					newrules.NetWhiteListPosture = true
					newrules.NetworkRuleList[key] = val

				} else if net.Action == "Block" {
					val[NETWORK] = val[NETWORK] | DENY
					newrules.NetworkRuleList[key] = val
				}
			} else {
				for _, src := range net.FromSource {
					var source [256]byte
					copy(source[:], []byte(src.Path))
					key.Source = source
					if net.Action == "Allow" {
						newrules.NetWhiteListPosture = true
						newrules.NetworkRuleList[key] = val

					} else if net.Action == "Block" {
						val[NETWORK] = val[NETWORK] | DENY
						newrules.NetworkRuleList[key] = val
					}

				}
			}
		}
		for _, capab := range secPolicy.Spec.Capabilities.MatchCapabilities {
			var val [2]uint8
			var key = InnerKey{Path: [256]byte{}, Source: [256]byte{}}

			key.Path[0] = capableKey

			// this will support both ( CAP_NET_RAW  and NET_RAW ) format type
			if !strings.Contains(capab.Capability, "cap_") {
				key.Path[1] = mon.CapToCode["CAP_"+strings.ToUpper(capab.Capability)]
			} else {
				key.Path[1] = mon.CapToCode[strings.ToUpper(capab.Capability)]
			}

			if len(capab.FromSource) == 0 {
				if capab.Action == "Allow" {
					newrules.CapWhiteListPosture = true
					newrules.CapabilitiesRuleList[key] = val

				} else if capab.Action == "Block" {
					val[CAPABILITIES] = val[CAPABILITIES] | DENY
					newrules.CapabilitiesRuleList[key] = val
				}
			} else {
				for _, src := range capab.FromSource {
					var source [256]byte
					copy(source[:], []byte(src.Path))
					key.Source = source
					if capab.Action == "Allow" {
						newrules.CapWhiteListPosture = true
						newrules.CapabilitiesRuleList[key] = val

					} else if capab.Action == "Block" {
						val[CAPABILITIES] = val[CAPABILITIES] | DENY
						newrules.CapabilitiesRuleList[key] = val
					}

				}
			}
		}
	}

	fuseProcAndFileRules(newrules.ProcessRuleList, newrules.FileRuleList)

	be.ContainerMapLock.Lock()
	defer be.ContainerMapLock.Unlock()

	// Check if Container ID is registered in Map or not
	if _, ok := be.ContainerMap[id]; !ok {
		// It maybe possible that CRI has unregistered the containers but K8s construct still has not sent this update while the policy was being applied,
		// so the need to check if the container is present in the map before we apply policy.
		return
	}

	if be.ContainerMap[id].Map == nil && !(len(newrules.FileRuleList) == 0 && len(newrules.ProcessRuleList) == 0 && len(newrules.NetworkRuleList) == 0 && len(newrules.CapabilitiesRuleList) == 0) {
		// We create the inner map only when we have policies specific to that
		be.Logger.Printf("Creating inner map for %s", id)
		be.CreateContainerInnerMap(id)
	} else if len(newrules.FileRuleList) == 0 && len(newrules.ProcessRuleList) == 0 && len(newrules.NetworkRuleList) == 0 && len(newrules.CapabilitiesRuleList) == 0 {
		// All Policies removed for the container
		be.Logger.Printf("Deleting inner map for %s", id)
		be.DeleteContainerInnerMap(id)
		return
	}

	// Check for differences in Fresh Rules Set and Existing Ruleset
	be.resolveConflicts(newrules.ProcWhiteListPosture, be.ContainerMap[id].Rules.ProcWhiteListPosture, newrules.ProcessRuleList, be.ContainerMap[id].Rules.ProcessRuleList, be.ContainerMap[id].Map)
	be.resolveConflicts(newrules.FileWhiteListPosture, be.ContainerMap[id].Rules.FileWhiteListPosture, newrules.FileRuleList, be.ContainerMap[id].Rules.FileRuleList, be.ContainerMap[id].Map)
	be.resolveConflicts(newrules.NetWhiteListPosture, be.ContainerMap[id].Rules.NetWhiteListPosture, newrules.NetworkRuleList, be.ContainerMap[id].Rules.NetworkRuleList, be.ContainerMap[id].Map)
	be.resolveConflicts(newrules.CapWhiteListPosture, be.ContainerMap[id].Rules.CapWhiteListPosture, newrules.CapabilitiesRuleList, be.ContainerMap[id].Rules.CapabilitiesRuleList, be.ContainerMap[id].Map)

	// Update Posture
	if list, ok := be.ContainerMap[id]; ok {
		list.Rules.ProcWhiteListPosture = newrules.ProcWhiteListPosture
		list.Rules.FileWhiteListPosture = newrules.FileWhiteListPosture
		list.Rules.NetWhiteListPosture = newrules.NetWhiteListPosture
		list.Rules.CapWhiteListPosture = newrules.CapWhiteListPosture

		be.ContainerMap[id] = list
	}

	if newrules.ProcWhiteListPosture {
		if defaultPosture.FileAction == "block" {
			if err := be.ContainerMap[id].Map.Put(PROCWHITELIST, [2]uint8{BlockPosture}); err != nil {
				be.Logger.Errf("error adding proc whitelist key rule to map for container %s: %s", id, err)
			}
		} else {
			if err := be.ContainerMap[id].Map.Put(PROCWHITELIST, [2]uint8{AuditPosture}); err != nil {
				be.Logger.Errf("error adding proc whitelist key rule to map for container %s: %s", id, err)
			}
		}

	} else {
		if err := be.ContainerMap[id].Map.Delete(PROCWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
	}
	for key, val := range newrules.ProcessRuleList {
		be.ContainerMap[id].Rules.ProcessRuleList[key] = val
		if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
			be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
		}
	}

	if newrules.FileWhiteListPosture {
		if defaultPosture.FileAction == "block" {
			if err := be.ContainerMap[id].Map.Put(FILEWHITELIST, [2]uint8{BlockPosture}); err != nil {
				be.Logger.Errf("error adding file whitelist key rule to map for container %s: %s", id, err)
			}
		} else {
			if err := be.ContainerMap[id].Map.Put(FILEWHITELIST, [2]uint8{AuditPosture}); err != nil {
				be.Logger.Errf("error adding file whitelist key rule to map for container %s: %s", id, err)
			}
		}
	} else {
		if err := be.ContainerMap[id].Map.Delete(FILEWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
	}
	for key, val := range newrules.FileRuleList {
		be.ContainerMap[id].Rules.FileRuleList[key] = val
		if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
			be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
		}
	}

	if newrules.NetWhiteListPosture {
		if defaultPosture.NetworkAction == "block" {
			if err := be.ContainerMap[id].Map.Put(NETWHITELIST, [2]uint8{BlockPosture}); err != nil {
				be.Logger.Errf("error adding network key rule to map for container %s: %s", id, err)
			}
		} else {
			if err := be.ContainerMap[id].Map.Put(NETWHITELIST, [2]uint8{AuditPosture}); err != nil {
				be.Logger.Errf("error adding network key rule to map for container %s: %s", id, err)
			}
		}
	} else {
		if err := be.ContainerMap[id].Map.Delete(NETWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
	}
	for key, val := range newrules.NetworkRuleList {
		be.ContainerMap[id].Rules.NetworkRuleList[key] = val
		if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
			be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
		}
	}
	if newrules.CapWhiteListPosture {
		if defaultPosture.CapabilitiesAction == "block" {
			if err := be.ContainerMap[id].Map.Put(CAPWHITELIST, [2]uint8{BlockPosture}); err != nil {
				be.Logger.Errf("error adding network key rule to map for container %s: %s", id, err)
			}
		} else {
			if err := be.ContainerMap[id].Map.Put(CAPWHITELIST, [2]uint8{AuditPosture}); err != nil {
				be.Logger.Errf("error adding network key rule to map for container %s: %s", id, err)
			}
		}
	} else {
		if err := be.ContainerMap[id].Map.Delete(CAPWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
	}
	for key, val := range newrules.CapabilitiesRuleList {
		be.ContainerMap[id].Rules.CapabilitiesRuleList[key] = val
		if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
			be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
		}
	}
}

func fuseProcAndFileRules(procList, fileList map[InnerKey][2]uint8) {
	for k, v := range fileList {
		if val, ok := procList[k]; ok {
			v[PROCESS] = val[PROCESS]
			fileList[k] = v
		}
	}
}

func (be *BPFEnforcer) resolveConflicts(_, _ bool, newRuleList, oldRuleList map[InnerKey][2]uint8, cmap *ebpf.Map) {
	// We delete existing elements which are not in the fresh rule set
	for key := range oldRuleList {
		if _, ok := newRuleList[key]; !ok {
			// Delete Element from Container Map
			if err := cmap.Delete(key); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					be.Logger.Err(err.Error())
				}
			}
			delete(oldRuleList, key)
		}
	}
}

// dirtoMap extracts parent directories from the Path Key and adds it as hints in the Container Rule Map
func dirtoMap(idx int, p, src string, m map[InnerKey][2]uint8, val [2]uint8) {
	var key InnerKey
	if src != "" {
		copy(key.Source[:], []byte(src))
	}
	paths := strings.Split(p, "/")

	// Add the directory itself but kernel space would refer it as a file so...
	var pth [256]byte
	copy(pth[:], []byte(strings.Join(paths[0:len(paths)-1], "/")))
	key.Path = pth
	m[key] = val

	// Add directory for sub file matching
	copy(key.Path[:], []byte(p))

	val[idx] = val[idx] | DIR
	if oldval, ok := m[key]; ok {
		if oldval[idx]&HINT != 0 {
			val[idx] = val[idx] | HINT
		}
	}
	m[key] = val

	for i := 1; i < len(paths)-1; i++ {
		var key InnerKey
		val[idx] = val[idx] & ^DIR // reset DIR mask to false
		val[idx] = val[idx] | HINT
		var hint = strings.Join(paths[0:i], "/") + "/"
		copy(key.Path[:], []byte(hint))
		if src != "" {
			copy(key.Source[:], []byte(src))
		}
		if oldval, ok := m[key]; ok {
			if oldval[idx]&DIR != 0 {
				val[idx] = oldval[idx] | HINT
			}
		}
		m[key] = val
	}
}
