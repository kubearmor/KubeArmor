// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package bpflsm is responsible for setting/cleaning up objects for BPF LSM enforcer and handle updates for the same
package bpflsm

import (
	"errors"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang enforcer ../../BPF/enforcer.bpf.c -- -I/usr/include/bpf -O2 -g

// ===================== //
// == BPFLSM Enforcer == //
// ===================== //

// BPFEnforcer structure to maintains relevant objects for BPF LSM Enforcement
type BPFEnforcer struct {
	Logger *fd.Feeder

	InnerMapSpec    *ebpf.MapSpec
	BPFContainerMap *ebpf.Map

	// ContainerID -> NsKey + rules
	ContainerMap     map[string]ContainerKV
	ContainerMapLock *sync.RWMutex

	obj enforcerObjects

	Probes map[string]link.Link
}

// NewBPFEnforcer instantiates a objects for setting up BPF LSM Enforcement
func NewBPFEnforcer(node tp.Node, logger *fd.Feeder) (*BPFEnforcer, error) {

	be := &BPFEnforcer{}

	be.Logger = logger

	var err error

	if err := rlimit.RemoveMemlock(); err != nil {
		be.Logger.Errf("Error removing rlimit %v", err)
		return nil, nil // Doesn't require clean up so not returning err
	}

	be.Probes = make(map[string]link.Link)
	be.ContainerMap = make(map[string]ContainerKV)
	be.ContainerMapLock = new(sync.RWMutex)

	be.InnerMapSpec = &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    512,
		ValueSize:  2,
		MaxEntries: 256,
	}

	be.BPFContainerMap, err = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.HashOfMaps,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 256,
		Pinning:    ebpf.PinByName,
		InnerMap:   be.InnerMapSpec,
		Name:       "kubearmor_containers",
	}, ebpf.MapOptions{
		PinPath: "/sys/fs/bpf",
	})
	if err != nil {
		be.Logger.Errf("error creating kubearmor_containers map: %s", err)
		return be, err
	}

	if err := loadEnforcerObjects(&be.obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		be.Logger.Errf("error loading BPF LSM objects: %v", err)
		return be, err
	}

	be.Probes[be.obj.EnforceProc.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceProc})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceProc.String(), err)
		return be, err
	}

	be.Probes[be.obj.EnforceFile.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceFile})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceFile.String(), err)
		return be, err
	}

	be.Probes[be.obj.EnforceFilePerm.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceFilePerm})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceFilePerm.String(), err)
		return be, err
	}

	be.Probes[be.obj.EnforceNetConnect.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceNetConnect})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceNetConnect.String(), err)
		return be, err
	}

	be.Probes[be.obj.EnforceNetAccept.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceNetAccept})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceNetAccept.String(), err)
		return be, err
	}

	if cfg.GlobalCfg.HostPolicy {
		be.AddHostToMap()
	}

	return be, nil
}

// UpdateSecurityPolicies loops through containers present in the input endpoint and updates rules for each container
func (be *BPFEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if BPFEnforcer is not active
	if be == nil {
		return
	}

	for _, cid := range endPoint.Containers {
		be.Logger.Printf("Updating container rules for %s", cid)
		be.UpdateContainerRules(cid, endPoint.SecurityPolicies, endPoint.DefaultPosture)
	}

}

// UpdateHostSecurityPolicies updates rules for the host
func (be *BPFEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if BPFEnforcer is not active
	if be == nil {
		return
	}

	be.Logger.Print("Updating host rules")
	be.UpdateHostRules(secPolicies)

}

// DestroyBPFEnforcer cleans up the objects for BPF LSM Enforcer
func (be *BPFEnforcer) DestroyBPFEnforcer() error {
	if be == nil {
		return nil
	}

	errBPFCleanUp := false

	if err := be.obj.Close(); err != nil {
		be.Logger.Err(err.Error())
		errBPFCleanUp = true
	}

	for _, link := range be.Probes {
		if err := link.Close(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = true
		}
	}

	be.ContainerMapLock.Lock()
	defer be.ContainerMapLock.Unlock()

	if be.BPFContainerMap != nil {
		if err := be.BPFContainerMap.Unpin(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = true
		}
		if err := be.BPFContainerMap.Close(); err != nil {
			be.Logger.Err(err.Error())
			errBPFCleanUp = true
		}
	}

	if errBPFCleanUp {
		return errors.New("error cleaning up BPF LSM Enforcer Objects")
	}

	be = nil
	return nil
}
