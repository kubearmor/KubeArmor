// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	"errors"
	"os"

	"github.com/cilium/ebpf"
)

// ContainerKV contains Keys for individual container eBPF Map and the Map itself
type ContainerKV struct {
	Key   NsKey
	Map   *ebpf.Map
	Rules RuleList
}

// NsKey Structure acts as an Identifier for containers
type NsKey struct {
	PidNS uint32
	MntNS uint32
}

// InnerKey Structure contains Map Rule Identifier
type InnerKey struct {
	Path   [4096]byte
	Source [4096]byte
}

// AddContainerIDToMap adds container metadata to Outer eBPF container Map for initialising enforcement tracking and initiates an InnerMap to store the container specific rules
func (be *BPFEnforcer) AddContainerIDToMap(containerID string, pidns, mntns uint32) {
	key := NsKey{PidNS: pidns, MntNS: mntns}

	be.ContainerMapLock.Lock()
	defer be.ContainerMapLock.Unlock()

	im, err := ebpf.NewMap(be.InnerMapSpec)
	if err != nil {
		be.Logger.Errf("error creating container map for %s: %s", containerID, err)
		return
	}

	var rules RuleList

	rules.ProcessBlackList = make(map[InnerKey][8]byte)
	rules.ProcessWhiteList = make(map[InnerKey][8]byte)
	rules.ProcWhiteListPosture = false

	rules.FileBlackList = make(map[InnerKey][8]byte)
	rules.FileWhiteList = make(map[InnerKey][8]byte)
	rules.FileWhiteListPosture = false

	rules.NetworkBlackList = make(map[InnerKey][8]byte)
	rules.NetworkWhiteList = make(map[InnerKey][8]byte)
	rules.NetWhiteListPosture = false

	be.ContainerMap[containerID] = ContainerKV{Key: key, Map: im, Rules: rules}
	if err := be.BPFContainerMap.Put(key, im); err != nil {
		be.Logger.Errf("error adding container %s to outer map: %s", containerID, err)
	}
}

// DeleteContainerIDFromMap cleans up eBPF objects w.r.t to the container
func (be *BPFEnforcer) DeleteContainerIDFromMap(containerID string) {

	be.ContainerMapLock.Lock()
	defer be.ContainerMapLock.Unlock()
	if err := be.BPFContainerMap.Delete(be.ContainerMap[containerID].Key); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			be.Logger.Errf("error deleting container %s from outer map: %s", containerID, err.Error())
		}
	}
	if err := be.ContainerMap[containerID].Map.Close(); err != nil {
		be.Logger.Errf("error closing container map for %s: %s", containerID, err)
	}
	delete(be.ContainerMap, containerID)
}
