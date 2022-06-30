// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	"errors"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// Array Keys for Map Rule Data
const (
	OWNER     uint8 = 0
	READ      uint8 = 1
	WRITE     uint8 = 2
	EXEC      uint8 = 3
	DIR       uint8 = 4
	RECURSIVE uint8 = 5
	HINT      uint8 = 6
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
	ProcessWhiteList     map[InnerKey][8]byte
	ProcessBlackList     map[InnerKey][8]byte
	FileWhiteList        map[InnerKey][8]byte
	FileBlackList        map[InnerKey][8]byte
	NetworkWhiteList     map[InnerKey][8]byte
	NetworkBlackList     map[InnerKey][8]byte
	ProcWhiteListPosture bool
	FileWhiteListPosture bool
	NetWhiteListPosture  bool
}

// UpdateContainerRules updates individual container map with new rules and resolves conflicting rules
func (be *BPFEnforcer) UpdateContainerRules(id string, securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) {

	var newrules RuleList

	newrules.ProcessBlackList = make(map[InnerKey][8]byte)
	newrules.ProcessWhiteList = make(map[InnerKey][8]byte)
	newrules.ProcWhiteListPosture = false

	newrules.FileBlackList = make(map[InnerKey][8]byte)
	newrules.FileWhiteList = make(map[InnerKey][8]byte)
	newrules.FileWhiteListPosture = false

	newrules.NetworkBlackList = make(map[InnerKey][8]byte)
	newrules.NetworkWhiteList = make(map[InnerKey][8]byte)
	newrules.NetWhiteListPosture = false

	// Generate Fresh Rule Set based on Updated Security Policies
	for _, secPolicy := range securityPolicies {
		for _, path := range secPolicy.Spec.Process.MatchPaths {

			var val [8]byte
			val[EXEC] = 1
			if path.OwnerOnly {
				val[OWNER] = 1
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
			var val [8]byte
			val[EXEC] = 1
			if dir.OwnerOnly {
				val[OWNER] = 1
			}
			if dir.Recursive {
				val[RECURSIVE] = 1
			}
			if len(dir.FromSource) == 0 {
				if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
					newrules.ProcWhiteListPosture = true
					dirtoMap(dir.Directory, "", newrules.ProcessWhiteList, val)
				} else if dir.Action == "Block" && !newrules.ProcWhiteListPosture {
					dirtoMap(dir.Directory, "", newrules.ProcessBlackList, val)
				}
			} else {
				for _, src := range dir.FromSource {
					if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
						newrules.ProcWhiteListPosture = true
						dirtoMap(dir.Directory, src.Path, newrules.ProcessWhiteList, val)
					} else if dir.Action == "Block" && !newrules.ProcWhiteListPosture {
						dirtoMap(dir.Directory, src.Path, newrules.ProcessBlackList, val)
					}
				}
			}
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			var val [8]byte
			val[READ] = 1
			if path.OwnerOnly {
				val[OWNER] = 1
			}
			if !path.ReadOnly {
				val[WRITE] = 1
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
			var val [8]byte
			val[READ] = 1
			if dir.OwnerOnly {
				val[OWNER] = 1
			}
			if !dir.ReadOnly {
				val[WRITE] = 1
			}
			if dir.Recursive {
				val[RECURSIVE] = 1
			}
			if len(dir.FromSource) == 0 {
				if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
					newrules.FileWhiteListPosture = true
					dirtoMap(dir.Directory, "", newrules.FileWhiteList, val)
				} else if dir.Action == "Block" && !newrules.FileWhiteListPosture {
					dirtoMap(dir.Directory, "", newrules.FileBlackList, val)
				}
			} else {
				for _, src := range dir.FromSource {
					if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
						newrules.FileWhiteListPosture = true
						dirtoMap(dir.Directory, src.Path, newrules.FileWhiteList, val)
					} else if dir.Action == "Block" && !newrules.FileWhiteListPosture {
						dirtoMap(dir.Directory, src.Path, newrules.FileBlackList, val)
					}
				}
			}
		}

		for _, net := range secPolicy.Spec.Network.MatchProtocols {
			var val [8]byte
			var key = InnerKey{Path: [256]byte{}}
			if val, ok := protocols[strings.ToUpper(net.Protocol)]; ok {
				key.Path[0] = PROTOCOL
				key.Path[1] = val
			} else if val, ok := netType[strings.ToUpper(net.Protocol)]; ok {
				key.Path[0] = TYPE
				key.Path[1] = val
			}

			if len(net.FromSource) == 0 {
				if net.Action == "Allow" && defaultPosture.FileAction == "block" {
					newrules.NetWhiteListPosture = true
					newrules.NetworkWhiteList[key] = val
				} else if net.Action == "Block" && !newrules.NetWhiteListPosture {
					newrules.NetworkBlackList[key] = val
				}
			} else {
				for _, src := range net.FromSource {
					copy(key.Source[:], []byte(src.Path))
					if net.Action == "Allow" && defaultPosture.FileAction == "block" {
						newrules.NetWhiteListPosture = true
						newrules.NetworkWhiteList[key] = val
					} else if net.Action == "Block" && !newrules.NetWhiteListPosture {
						newrules.NetworkBlackList[key] = val
					}

				}
			}
		}
	}

	// Check for differences in Fresh Rules Set and Existing Ruleset
	be.resolveConflicts(newrules.ProcWhiteListPosture, be.ContainerMap[id].Rules.ProcWhiteListPosture, newrules.ProcessBlackList, be.ContainerMap[id].Rules.ProcessBlackList, newrules.ProcessWhiteList, be.ContainerMap[id].Rules.ProcessWhiteList, be.ContainerMap[id].Map)
	be.resolveConflicts(newrules.FileWhiteListPosture, be.ContainerMap[id].Rules.FileWhiteListPosture, newrules.FileBlackList, be.ContainerMap[id].Rules.FileBlackList, newrules.FileWhiteList, be.ContainerMap[id].Rules.FileWhiteList, be.ContainerMap[id].Map)
	be.resolveConflicts(newrules.NetWhiteListPosture, be.ContainerMap[id].Rules.NetWhiteListPosture, newrules.NetworkBlackList, be.ContainerMap[id].Rules.NetworkBlackList, newrules.NetworkWhiteList, be.ContainerMap[id].Rules.NetworkWhiteList, be.ContainerMap[id].Map)

	if newrules.ProcWhiteListPosture {
		if err := be.ContainerMap[id].Map.Put(PROCWHITELIST, [8]byte{}); err != nil {
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
		if err := be.ContainerMap[id].Map.Put(FILEWHITELIST, [8]byte{}); err != nil {
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
			var i uint32
			err := be.BPFContainerMap.Lookup(be.ContainerMap[id].Key, &i)
			if err != nil {
				log.Fatalf("error looking map: %s", err)
			}
			log.Println(i)
		}
	}

	if newrules.NetWhiteListPosture {
		if err := be.ContainerMap[id].Map.Put(NETWHITELIST, [8]byte{}); err != nil {
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

func (be *BPFEnforcer) resolveConflicts(newPosture, oldPosture bool, newBlackList, oldBlackList, newWhiteList, oldWhiteList map[InnerKey][8]byte, cmap *ebpf.Map) {
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
func dirtoMap(p, src string, m map[InnerKey][8]byte, val [8]byte) {
	var key InnerKey
	copy(key.Path[:], []byte(p))
	if src != "" {
		copy(key.Source[:], []byte(src))
	}
	paths := strings.Split(p, "/")
	val[DIR] = 1
	m[key] = val

	val[DIR] = 0

	for i := 1; i < len(paths)-1; i++ {
		var key InnerKey
		val[HINT] = 1
		var hint = strings.Join(paths[0:i], "/") + "/"
		copy(key.Path[:], []byte(hint))
		if src != "" {
			copy(key.Source[:], []byte(src))
		}
		m[key] = val
	}
}
