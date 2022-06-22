// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	"errors"
	"os"
	"strings"

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

type RuleList struct {
	ProcessWhiteList     map[uint32][8]byte
	ProcessBlackList     map[uint32][8]byte
	ProcWhiteListPosture bool
}

func (be *BPFEnforcer) UpdateContainerRules(id string, securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) {

	var newrules RuleList

	newrules.ProcessWhiteList = make(map[uint32][8]byte)
	newrules.ProcessBlackList = make(map[uint32][8]byte)

	newrules.ProcWhiteListPosture = false

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
	}

	// Check for differences in Fresh Rules Set and Existing Ruleset

	// No change in default posture, we delete existing elements which are not in the fresh rule set
	if newrules.ProcWhiteListPosture == be.ContainerMap[id].Rules.ProcWhiteListPosture {
		if newrules.ProcWhiteListPosture {
			for key := range be.ContainerMap[id].Rules.ProcessWhiteList {
				if _, ok := newrules.ProcessWhiteList[key]; !ok {
					// Delete Element from Container Map
					if err := be.ContainerMap[id].Map.Delete(key); err != nil {
						if !errors.Is(err, os.ErrNotExist) {
							be.Logger.Err(err.Error())
						}
					}
					delete(be.ContainerMap[id].Rules.ProcessBlackList, key)
				}
			}
		} else {
			for key := range be.ContainerMap[id].Rules.ProcessBlackList {
				if _, ok := newrules.ProcessBlackList[key]; !ok {
					// Delete Element from Container Map
					if err := be.ContainerMap[id].Map.Delete(key); err != nil {
						if !errors.Is(err, os.ErrNotExist) {
							be.Logger.Err(err.Error())
						}
					}
					delete(be.ContainerMap[id].Rules.ProcessWhiteList, key)
				}
			}
		}
	}

	// Change in default posture, We batch delete all the elements
	if newrules.ProcWhiteListPosture != be.ContainerMap[id].Rules.ProcWhiteListPosture {
		var keys []uint32
		if newrules.ProcWhiteListPosture {
			for key := range be.ContainerMap[id].Rules.ProcessBlackList {
				keys = append(keys, key)
				delete(be.ContainerMap[id].Rules.ProcessBlackList, key)
			}
		} else {
			for key := range be.ContainerMap[id].Rules.ProcessWhiteList {
				keys = append(keys, key)
				delete(be.ContainerMap[id].Rules.ProcessWhiteList, key)
			}
		}
		count, err := be.ContainerMap[id].Map.BatchDelete(keys, nil)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Err(err.Error())
			}
		}
		be.Logger.Printf("Batch deleted due to change in posture %d", count)
	}

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
