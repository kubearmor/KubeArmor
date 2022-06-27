// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	"errors"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	cm "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

const (
	OWNER     uint8 = 0
	READ      uint8 = 1
	WRITE     uint8 = 2
	EXEC      uint8 = 3
	DIR       uint8 = 4
	RECURSIVE uint8 = 5
	HINT      uint8 = 6
)

const (
	PROCWHITELIST uint32 = 101
	FILEWHITELIST uint32 = 102
	NETWHITELIST  uint32 = 103
)

var protocols = map[string]uint32{
	"ICMP":   1,
	"TCP":    6,
	"UDP":    17,
	"ICMPv6": 58,
}

type RuleList struct {
	ProcessWhiteList     map[uint32][8]byte
	ProcessBlackList     map[uint32][8]byte
	FileWhiteList        map[uint32][8]byte
	FileBlackList        map[uint32][8]byte
	NetworkWhiteList     map[uint32][8]byte
	NetworkBlackList     map[uint32][8]byte
	ProcWhiteListPosture bool
	FileWhiteListPosture bool
	NetWhiteListPosture  bool
}

func (be *BPFEnforcer) UpdateContainerRules(id string, securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) {

	var newrules RuleList

	newrules.ProcessBlackList = make(map[uint32][8]byte)
	newrules.ProcessWhiteList = make(map[uint32][8]byte)
	newrules.ProcWhiteListPosture = false

	newrules.FileBlackList = make(map[uint32][8]byte)
	newrules.FileWhiteList = make(map[uint32][8]byte)
	newrules.FileWhiteListPosture = false

	newrules.NetworkBlackList = make(map[uint32][8]byte)
	newrules.NetworkWhiteList = make(map[uint32][8]byte)
	newrules.NetWhiteListPosture = false

	// Generate Fresh Rule Set based on Updated Security Policies
	for _, secPolicy := range securityPolicies {
		for _, path := range secPolicy.Spec.Process.MatchPaths {
			var val [8]byte
			val[EXEC] = 1
			if path.OwnerOnly {
				val[OWNER] = 1
			}
			if path.Action == "Allow" && defaultPosture.FileAction == "block" {
				newrules.ProcWhiteListPosture = true
				newrules.ProcessWhiteList[cm.JHash([]byte(path.Path), 0)] = val
			} else if path.Action == "Block" && !newrules.ProcWhiteListPosture {
				newrules.ProcessBlackList[cm.JHash([]byte(path.Path), 0)] = val
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
			if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
				newrules.ProcWhiteListPosture = true
				dirtoMap(dir.Directory, newrules.ProcessWhiteList, val)
			} else if dir.Action == "Block" && !newrules.ProcWhiteListPosture {
				dirtoMap(dir.Directory, newrules.ProcessBlackList, val)
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
			if path.Action == "Allow" && defaultPosture.FileAction == "block" {
				newrules.FileWhiteListPosture = true
				newrules.FileWhiteList[cm.JHash([]byte(path.Path), 0)] = val
			} else if path.Action == "Block" && !newrules.FileWhiteListPosture {
				newrules.FileBlackList[cm.JHash([]byte(path.Path), 0)] = val
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
			if dir.Action == "Allow" && defaultPosture.FileAction == "block" {
				newrules.FileWhiteListPosture = true
				dirtoMap(dir.Directory, newrules.FileWhiteList, val)
			} else if dir.Action == "Block" && !newrules.FileWhiteListPosture {
				dirtoMap(dir.Directory, newrules.FileBlackList, val)
			}
		}

		for _, net := range secPolicy.Spec.Network.MatchProtocols {
			var val [8]byte
			var key uint32 = 0xdeadbeef + protocols[strings.ToUpper(net.Protocol)]
			if net.Action == "Allow" && defaultPosture.FileAction == "block" {
				newrules.NetWhiteListPosture = true
				newrules.NetworkWhiteList[key] = val
			} else if net.Action == "Block" && !newrules.NetWhiteListPosture {
				newrules.NetworkBlackList[key] = val
			}
		}
	}

	// Check for differences in Fresh Rules Set and Existing Ruleset
	be.resolveConflicts(newrules.ProcWhiteListPosture, be.ContainerMap[id].Rules.ProcWhiteListPosture, newrules.ProcessBlackList, be.ContainerMap[id].Rules.ProcessBlackList, newrules.ProcessWhiteList, be.ContainerMap[id].Rules.ProcessWhiteList, be.ContainerMap[id].Map)
	be.resolveConflicts(newrules.FileWhiteListPosture, be.ContainerMap[id].Rules.FileWhiteListPosture, newrules.FileBlackList, be.ContainerMap[id].Rules.FileBlackList, newrules.FileWhiteList, be.ContainerMap[id].Rules.FileWhiteList, be.ContainerMap[id].Map)
	be.resolveConflicts(newrules.NetWhiteListPosture, be.ContainerMap[id].Rules.NetWhiteListPosture, newrules.NetworkBlackList, be.ContainerMap[id].Rules.NetworkBlackList, newrules.NetworkWhiteList, be.ContainerMap[id].Rules.NetworkWhiteList, be.ContainerMap[id].Map)

	if newrules.ProcWhiteListPosture {
		be.ContainerMap[id].Map.Put(PROCWHITELIST, [8]byte{})
		for key, val := range newrules.ProcessWhiteList {
			be.ContainerMap[id].Rules.ProcessWhiteList[key] = val
			be.ContainerMap[id].Map.Put(key, val)
		}
	} else {
		if err := be.ContainerMap[id].Map.Delete(PROCWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
		for key, val := range newrules.ProcessBlackList {
			be.ContainerMap[id].Rules.ProcessBlackList[key] = val
			be.ContainerMap[id].Map.Put(key, val)
		}
	}

	if newrules.FileWhiteListPosture {
		be.ContainerMap[id].Map.Put(FILEWHITELIST, [8]byte{})
		for key, val := range newrules.FileWhiteList {
			be.ContainerMap[id].Rules.FileWhiteList[key] = val
			be.ContainerMap[id].Map.Put(key, val)
		}
	} else {
		if err := be.ContainerMap[id].Map.Delete(FILEWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
		for key, val := range newrules.FileBlackList {
			be.ContainerMap[id].Rules.FileBlackList[key] = val
			be.ContainerMap[id].Map.Put(key, val)
		}
	}

	if newrules.NetWhiteListPosture {
		be.ContainerMap[id].Map.Put(NETWHITELIST, [8]byte{})
		for key, val := range newrules.NetworkWhiteList {
			be.ContainerMap[id].Rules.NetworkWhiteList[key] = val
			be.ContainerMap[id].Map.Put(key, val)
		}
	} else {
		if err := be.ContainerMap[id].Map.Delete(NETWHITELIST); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
		for key, val := range newrules.NetworkBlackList {
			be.ContainerMap[id].Rules.NetworkBlackList[key] = val
			be.ContainerMap[id].Map.Put(key, val)
		}
	}
}

func (be *BPFEnforcer) resolveConflicts(newPosture, oldPosture bool, newBlackList, oldBlackList, newWhiteList, oldWhiteList map[uint32][8]byte, cmap *ebpf.Map) {
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

	// Change in default posture, We batch delete all the elements
	if newPosture != oldPosture {
		var keys []uint32
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

func dirtoMap(p string, m map[uint32][8]byte, val [8]byte) {
	paths := strings.Split(p, "/")
	val[DIR] = 1
	m[cm.JHash([]byte(p), 0)] = val

	val[DIR] = 0

	for i := 1; i < len(paths)-1; i++ {
		val[HINT] = 1
		var hint string = strings.Join(paths[0:i], "/") + "/"
		m[cm.JHash([]byte(hint), 0)] = val
	}
}
