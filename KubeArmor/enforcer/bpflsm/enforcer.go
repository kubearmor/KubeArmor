// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package bpflsm

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang enforcer ../../BPF/enforcer.bpf.c -- -I/usr/include/bpf -O2 -g

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

func NewBPFEnforcer(node tp.Node, logger *fd.Feeder) *BPFEnforcer {

	be := &BPFEnforcer{}

	be.Logger = logger

	var err error

	if err := rlimit.RemoveMemlock(); err != nil {
		be.Logger.Errf("Error removing rlimit %v", err)
		return nil
	}

	be.InnerMapSpec = &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1024,
	}

	be.BPFContainerMap, err = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.HashOfMaps,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 1024,
		Pinning:    ebpf.PinByName,
		InnerMap:   be.InnerMapSpec,
		Name:       "kubearmor_containers",
	}, ebpf.MapOptions{
		PinPath: "/sys/fs/bpf",
	})
	if err != nil {
		be.Logger.Errf("error creating kubearmor_containers map: %s", err)
		return nil
	}

	if err := loadEnforcerObjects(&be.obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		be.Logger.Errf("error loading BPF LSM objects: %v", err)
		return nil
	}

	be.Probes = make(map[string]link.Link)
	be.ContainerMap = make(map[string]ContainerKV)
	be.ContainerMapLock = new(sync.RWMutex)

	be.Probes[be.obj.EnforceProc.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceProc})
	if err != nil {
		be.Logger.Errf("opening kprobe %s: %s", be.obj.EnforceProc.String(), err)
		return nil
	}

	return be
}

func (be *BPFEnforcer) DestroyBPFEnforcer() error {
	if be == nil {
		return nil
	}

	if err := be.obj.Close(); err != nil {
		return err
	}

	if be.BPFContainerMap != nil {
		if err := be.BPFContainerMap.Unpin(); err != nil {
			return err
		}
		if err := be.BPFContainerMap.Close(); err != nil {
			return err
		}
	}

	for _, link := range be.Probes {
		if err := link.Close(); err != nil {
			return err
		}
	}
	return nil
}
