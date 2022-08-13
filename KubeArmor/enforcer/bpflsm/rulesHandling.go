// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	"errors"
	"os"
	"strings"

	"github.com/cilium/ebpf"
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
	PROCESS = 0
	FILE    = 1
)

// Map Key Identifiers for Whitelist/Posture
var (
	PROCWHITELIST = InnerKey{Path: [256]byte{101}}
	FILEWHITELIST = InnerKey{Path: [256]byte{102}}
	NETWHITELIST  = InnerKey{Path: [256]byte{103}}
)

// Protocol Identifiers for Network Rules
var protocols = map[string]uint8{
	"ICMP":   1,
	"TCP":    6,
	"UDP":    17,
	"ICMPv6": 58,
}

// Socket Type Identifiers for Network Rules
var netType = map[string]uint8{
	"RAW": 3,
}

// Array Keys for Network Rule Keys
const (
	FAMILY   uint8 = 1
	TYPE     uint8 = 2
	PROTOCOL uint8 = 3
)

// RuleList Structure contains all the data required to set rules for a particular container
type RuleList struct {
	ProcessWhiteList     map[InnerKey][2]uint8
	ProcessBlackList     map[InnerKey][2]uint8
	FileWhiteList        map[InnerKey][2]uint8
	FileBlackList        map[InnerKey][2]uint8
	NetworkWhiteList     map[InnerKey][2]uint8
	NetworkBlackList     map[InnerKey][2]uint8
	ProcWhiteListPosture bool
	FileWhiteListPosture bool
	NetWhiteListPosture  bool
}

// Init prepares the RuleList object
func (r *RuleList) Init() {
	r.ProcessBlackList = make(map[InnerKey][2]uint8)
	r.ProcessWhiteList = make(map[InnerKey][2]uint8)
	r.ProcWhiteListPosture = false

	r.FileBlackList = make(map[InnerKey][2]uint8)
	r.FileWhiteList = make(map[InnerKey][2]uint8)
	r.FileWhiteListPosture = false

	r.NetworkBlackList = make(map[InnerKey][2]uint8)
	r.NetworkWhiteList = make(map[InnerKey][2]uint8)
	r.NetWhiteListPosture = false
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
				copy(key.Path[:], []byte(path.Path))
				if path.Action == "Allow" && defaultPosture.FileAction == "block" {
					newrules.ProcWhiteListPosture = true
					newrules.ProcessWhiteList[key] = val
				} else if path.Action == "Block" && !newrules.ProcWhiteListPosture {
					newrules.ProcessBlackList[key] = val
				}
			} else {
				for _, src := range path.FromSource {
					var key InnerKey
					copy(key.Path[:], []byte(path.Path))
					copy(key.Source[:], []byte(src.Path))
					if path.Action == "Allow" && defaultPosture.FileAction == "block" {
						newrules.ProcWhiteListPosture = true
						newrules.ProcessWhiteList[key] = val
					} else if path.Action == "Block" && !newrules.ProcWhiteListPosture {
						newrules.ProcessBlackList[key] = val
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
				if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
					newrules.ProcWhiteListPosture = true
					dirtoMap(PROCESS, dir.Directory, "", newrules.ProcessWhiteList, val)
				} else if dir.Action == "Block" && !newrules.ProcWhiteListPosture {
					dirtoMap(PROCESS, dir.Directory, "", newrules.ProcessBlackList, val)
				}
			} else {
				for _, src := range dir.FromSource {
					if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
						newrules.ProcWhiteListPosture = true
						dirtoMap(PROCESS, dir.Directory, src.Path, newrules.ProcessWhiteList, val)
					} else if dir.Action == "Block" && !newrules.ProcWhiteListPosture {
						dirtoMap(PROCESS, dir.Directory, src.Path, newrules.ProcessBlackList, val)
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
				if path.Action == "Allow" && defaultPosture.FileAction == "block" {
					newrules.FileWhiteListPosture = true
					newrules.FileWhiteList[key] = val
				} else if path.Action == "Block" && !newrules.FileWhiteListPosture {
					newrules.FileBlackList[key] = val
				}
			} else {
				for _, src := range path.FromSource {
					var key InnerKey
					copy(key.Path[:], []byte(path.Path))
					copy(key.Source[:], []byte(src.Path))
					if path.Action == "Allow" && defaultPosture.FileAction == "block" {
						newrules.FileWhiteListPosture = true
						newrules.FileWhiteList[key] = val
					} else if path.Action == "Block" && !newrules.FileWhiteListPosture {
						newrules.FileBlackList[key] = val
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
				if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
					newrules.FileWhiteListPosture = true
					dirtoMap(FILE, dir.Directory, "", newrules.FileWhiteList, val)
				} else if dir.Action == "Block" && !newrules.FileWhiteListPosture {
					dirtoMap(FILE, dir.Directory, "", newrules.FileBlackList, val)
				}
			} else {
				for _, src := range dir.FromSource {
					if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
						newrules.FileWhiteListPosture = true
						dirtoMap(FILE, dir.Directory, src.Path, newrules.FileWhiteList, val)
					} else if dir.Action == "Block" && !newrules.FileWhiteListPosture {
						dirtoMap(FILE, dir.Directory, src.Path, newrules.FileBlackList, val)
					}
				}
			}
		}

		for _, net := range secPolicy.Spec.Network.MatchProtocols {
			var val [2]uint8
			var key = InnerKey{Path: [256]byte{}}
			if val, ok := protocols[strings.ToUpper(net.Protocol)]; ok {
				key.Path[0] = PROTOCOL
				key.Path[1] = val
			} else if val, ok := netType[strings.ToUpper(net.Protocol)]; ok {
				key.Path[0] = TYPE
				key.Path[1] = val
			}

			if len(net.FromSource) == 0 {
				if net.Action == "Allow" && defaultPosture.NetworkAction == "block" {
					newrules.NetWhiteListPosture = true
					newrules.NetworkWhiteList[key] = val
				} else if net.Action == "Block" && !newrules.NetWhiteListPosture {
					newrules.NetworkBlackList[key] = val
				}
			} else {
				for _, src := range net.FromSource {
					copy(key.Source[:], []byte(src.Path))
					if net.Action == "Allow" && defaultPosture.NetworkAction == "block" {
						newrules.NetWhiteListPosture = true
						newrules.NetworkWhiteList[key] = val
					} else if net.Action == "Block" && !newrules.NetWhiteListPosture {
						newrules.NetworkBlackList[key] = val
					}

				}
			}
		}
	}

	be.ContainerMapLock.Lock()
	defer be.ContainerMapLock.Unlock()

	// Check if Container ID is registered in Map or not
	if _, ok := be.ContainerMap[id]; !ok {
		// It maybe possible that CRI has unregistered the containers but K8s construct still has not sent this update while the policy was being applied,
		// so the need to check if the container is present in the map before we apply policy.
		return
	}

	// Check for differences in Fresh Rules Set and Existing Ruleset
	be.resolveConflicts(newrules.ProcWhiteListPosture, be.ContainerMap[id].Rules.ProcWhiteListPosture, newrules.ProcessBlackList, be.ContainerMap[id].Rules.ProcessBlackList, newrules.ProcessWhiteList, be.ContainerMap[id].Rules.ProcessWhiteList, be.ContainerMap[id].Map)
	be.resolveConflicts(newrules.FileWhiteListPosture, be.ContainerMap[id].Rules.FileWhiteListPosture, newrules.FileBlackList, be.ContainerMap[id].Rules.FileBlackList, newrules.FileWhiteList, be.ContainerMap[id].Rules.FileWhiteList, be.ContainerMap[id].Map)
	be.resolveConflicts(newrules.NetWhiteListPosture, be.ContainerMap[id].Rules.NetWhiteListPosture, newrules.NetworkBlackList, be.ContainerMap[id].Rules.NetworkBlackList, newrules.NetworkWhiteList, be.ContainerMap[id].Rules.NetworkWhiteList, be.ContainerMap[id].Map)

	// Update Posture
	if list, ok := be.ContainerMap[id]; ok {
		list.Rules.ProcWhiteListPosture = newrules.ProcWhiteListPosture
		list.Rules.FileWhiteListPosture = newrules.FileWhiteListPosture
		list.Rules.NetWhiteListPosture = newrules.NetWhiteListPosture

		be.ContainerMap[id] = list
	}

	if newrules.ProcWhiteListPosture {
		if err := be.ContainerMap[id].Map.Put(PROCWHITELIST, [2]uint8{}); err != nil {
			be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
		}
		for key, val := range newrules.ProcessWhiteList {
			be.ContainerMap[id].Rules.ProcessWhiteList[key] = val
			if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
				be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
			}
		}
	} else {
		if err := be.ContainerMap[id].Map.Delete(PROCWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
		for key, val := range newrules.ProcessBlackList {
			be.ContainerMap[id].Rules.ProcessBlackList[key] = val
			if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
				be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
			}
		}
	}

	if newrules.FileWhiteListPosture {
		if err := be.ContainerMap[id].Map.Put(FILEWHITELIST, [2]uint8{}); err != nil {
			be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
		}
		for key, val := range newrules.FileWhiteList {
			be.ContainerMap[id].Rules.FileWhiteList[key] = val
			if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
				be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
			}
		}
	} else {
		if err := be.ContainerMap[id].Map.Delete(FILEWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
		for key, val := range newrules.FileBlackList {
			be.ContainerMap[id].Rules.FileBlackList[key] = val
			if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
				be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
			}
		}
	}

	if newrules.NetWhiteListPosture {
		if err := be.ContainerMap[id].Map.Put(NETWHITELIST, [2]uint8{}); err != nil {
			be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
		}
		for key, val := range newrules.NetworkWhiteList {
			be.ContainerMap[id].Rules.NetworkWhiteList[key] = val
			if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
				be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
			}
		}
	} else {
		if err := be.ContainerMap[id].Map.Delete(NETWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
		for key, val := range newrules.NetworkBlackList {
			be.ContainerMap[id].Rules.NetworkBlackList[key] = val
			if err := be.ContainerMap[id].Map.Put(key, val); err != nil {
				be.Logger.Errf("error adding rule to map for container %s: %s", id, err)
			}
		}
	}
}

func (be *BPFEnforcer) resolveConflicts(newPosture, oldPosture bool, newBlackList, oldBlackList, newWhiteList, oldWhiteList map[InnerKey][2]uint8, cmap *ebpf.Map) {
	// No change in default posture, we delete existing elements which are not in the fresh rule set
	if newPosture == oldPosture {
		if newPosture {
			for key := range oldWhiteList {
				if _, ok := newWhiteList[key]; !ok {
					// Delete Element from Container Map
					if err := cmap.Delete(key); err != nil {
						if !errors.Is(err, os.ErrNotExist) {
							be.Logger.Err(err.Error())
						}
					}
					delete(oldBlackList, key)
				}
			}
		} else {
			for key := range oldBlackList {
				if _, ok := newBlackList[key]; !ok {
					// Delete Element from Container Map
					if err := cmap.Delete(key); err != nil {
						if !errors.Is(err, os.ErrNotExist) {
							be.Logger.Err(err.Error())
						}
					}
					delete(oldWhiteList, key)
				}
			}
		}
	}

	// Change in default posture, We batch delete all existing elements
	if newPosture != oldPosture {
		var keys []InnerKey
		if newPosture {
			for key := range oldBlackList {
				keys = append(keys, key)
				delete(oldBlackList, key)
			}
		} else {
			for key := range oldWhiteList {
				keys = append(keys, key)
				delete(oldWhiteList, key)
			}
		}
		count, err := cmap.BatchDelete(keys, nil)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
		be.Logger.Printf("Batch deleted due to change in posture %d", count)
	}
}

// dirtoMap extracts parent directories from the Path Key and adds it as hints in the Container Rule Map
func dirtoMap(idx int, p, src string, m map[InnerKey][2]uint8, val [2]uint8) {
	var key InnerKey
	copy(key.Path[:], []byte(p))
	if src != "" {
		copy(key.Source[:], []byte(src))
	}
	paths := strings.Split(p, "/")
	val[idx] = val[idx] | DIR
	m[key] = val

	val[idx] = val[idx] ^ DIR // reset DIR mask to false

	for i := 1; i < len(paths)-1; i++ {
		var key InnerKey
		val[idx] = val[idx] | HINT
		var hint = strings.Join(paths[0:i], "/") + "/"
		copy(key.Path[:], []byte(hint))
		if src != "" {
			copy(key.Source[:], []byte(src))
		}
		m[key] = val
	}
}
