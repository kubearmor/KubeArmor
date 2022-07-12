// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	"errors"
	"os"
	"strings"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// UpdateHostRules updates host rules map with new rules and resolves conflicting rules
func (be *BPFEnforcer) UpdateHostRules(securityPolicies []tp.HostSecurityPolicy) {
	id := "host"

	var newrules RuleList

	newrules.Init()

	// Generate Fresh Rule Set based on Updated Security Policies
	for _, secPolicy := range securityPolicies {
		for _, path := range secPolicy.Spec.Process.MatchPaths {

			var val [8]byte
			val[EXEC] = 1
			val[READ] = 1 // Exec needs to pass through file open so need to provide this
			if path.OwnerOnly {
				val[OWNER] = 1
			}
			if len(path.FromSource) == 0 {
				var key InnerKey
				copy(key.Path[:], []byte(path.Path))
				if path.Action == "Allow" && cfg.GlobalCfg.HostDefaultFilePosture == "block" {
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
					if path.Action == "Allow" && cfg.GlobalCfg.HostDefaultFilePosture == "block" {
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
			val[READ] = 1 // Exec needs to pass through file open so need to provide this
			if dir.OwnerOnly {
				val[OWNER] = 1
			}
			if dir.Recursive {
				val[RECURSIVE] = 1
			}
			if len(dir.FromSource) == 0 {
				if dir.Action == "Allow" && cfg.GlobalCfg.HostDefaultFilePosture == "block" {
					newrules.ProcWhiteListPosture = true
					dirtoMap(dir.Directory, "", newrules.ProcessWhiteList, val)
				} else if dir.Action == "Block" && !newrules.ProcWhiteListPosture {
					dirtoMap(dir.Directory, "", newrules.ProcessBlackList, val)
				}
			} else {
				for _, src := range dir.FromSource {
					if dir.Action == "Allow" && cfg.GlobalCfg.HostDefaultFilePosture == "block" {
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
				if path.Action == "Allow" && cfg.GlobalCfg.HostDefaultFilePosture == "block" {
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
					if path.Action == "Allow" && cfg.GlobalCfg.HostDefaultFilePosture == "block" {
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
				if dir.Action == "Allow" && cfg.GlobalCfg.HostDefaultFilePosture == "block" {
					newrules.FileWhiteListPosture = true
					dirtoMap(dir.Directory, "", newrules.FileWhiteList, val)
				} else if dir.Action == "Block" && !newrules.FileWhiteListPosture {
					dirtoMap(dir.Directory, "", newrules.FileBlackList, val)
				}
			} else {
				for _, src := range dir.FromSource {
					if dir.Action == "Allow" && cfg.GlobalCfg.HostDefaultFilePosture == "block" {
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
				if net.Action == "Allow" && cfg.GlobalCfg.HostDefaultNetworkPosture == "block" {
					newrules.NetWhiteListPosture = true
					newrules.NetworkWhiteList[key] = val
				} else if net.Action == "Block" && !newrules.NetWhiteListPosture {
					newrules.NetworkBlackList[key] = val
				}
			} else {
				for _, src := range net.FromSource {
					copy(key.Source[:], []byte(src.Path))
					if net.Action == "Allow" && cfg.GlobalCfg.HostDefaultNetworkPosture == "block" {
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
