// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

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
	Path   [256]byte
	Source [256]byte
}

// AddContainerIDToMap adds container metadata to Outer eBPF container Map for initialising enforcement tracking and initiates an InnerMap to store the container specific rules
func (be *BPFEnforcer) AddContainerIDToMap(containerID string, pidns, mntns uint32) {
	key := NsKey{PidNS: pidns, MntNS: mntns}

	be.ContainerMapLock.Lock()
	defer be.ContainerMapLock.Unlock()

	var rules RuleList
	rules.Init()

	be.ContainerMap[containerID] = ContainerKV{Key: key, Rules: rules}
}

// AddContainerIDToMap adds container metadata to Outer eBPF container Map for initialising enforcement tracking and initiates an InnerMap to store the container specific rules
func (be *BPFEnforcer) CreateContainerInnerMap(containerID string) {

	if val, ok := be.ContainerMap[containerID]; ok {
		im, err := ebpf.NewMap(be.InnerMapSpec)
		if err != nil {
			be.Logger.Errf("error creating container map for %s: %s", containerID, err)
			return
		}

		be.ContainerMap[containerID] = ContainerKV{Key: val.Key, Map: im, Rules: val.Rules}
		if err := be.BPFContainerMap.Put(val.Key, im); err != nil {
			be.Logger.Errf("error adding container %s to outer map: %s", containerID, err)
		}
	}
}

// DeleteContainerIDFromMap cleans up eBPF objects w.r.t to the container
func (be *BPFEnforcer) DeleteContainerIDFromMap(containerID string) {

	be.ContainerMapLock.Lock()
	defer be.ContainerMapLock.Unlock()

	be.DeleteContainerInnerMap(containerID)
	delete(be.ContainerMap, containerID)
}

// AddContainerIDToMap adds container metadata to Outer eBPF container Map for initialising enforcement tracking and initiates an InnerMap to store the container specific rules
func (be *BPFEnforcer) DeleteContainerInnerMap(containerID string) {

	if be.ContainerMap[containerID].Map != nil {
		if err := be.BPFContainerMap.Delete(be.ContainerMap[containerID].Key); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Errf("error deleting container %s from outer map in kubearmor_containers map: %s", containerID, err.Error())
			}
		}
		if err := be.BPFContainerThrottleMap.Delete(be.ContainerMap[containerID].Key); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				be.Logger.Errf("error deleting container %s from outer map in kubearmor_alert_throttle map: %s", containerID, err.Error())
			}
		}
		if err := be.ContainerMap[containerID].Map.Close(); err != nil {
			be.Logger.Errf("error closing container map for %s: %s", containerID, err)
		}
		val := be.ContainerMap[containerID]
		val.Map = nil
		val.Rules.Init()
		be.ContainerMap[containerID] = val
	}
}

// AddHostToMap adds host to Outer eBPF container Map for initialising enforcement tracking and initiates an InnerMap to store the host specific rules
func (be *BPFEnforcer) AddHostToMap() {
	key := NsKey{PidNS: 0, MntNS: 0}

	be.ContainerMapLock.Lock()
	defer be.ContainerMapLock.Unlock()

	im, err := ebpf.NewMap(be.InnerMapSpec)
	if err != nil {
		be.Logger.Errf("error creating host policy map: %s", err)
		return
	}

	var rules RuleList

	rules.Init()

	be.ContainerMap["host"] = ContainerKV{Key: key, Map: im, Rules: rules}
	if err := be.BPFContainerMap.Put(key, im); err != nil {
		be.Logger.Errf("error adding host to outer map: %s", err)
	}
}
