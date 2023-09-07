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

	common "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang enforcer ../../BPF/enforcer.bpf.c -- -I/usr/include/bpf -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang enforcer_path ../../BPF/enforcer_path.bpf.c -- -I/usr/include/bpf -O2 -g

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

	obj     enforcerObjects
	objPath enforcer_pathObjects

	Probes map[string]link.Link
}

// NewBPFEnforcer instantiates a objects for setting up BPF LSM Enforcement
func NewBPFEnforcer(node tp.Node, pinpath string, logger *fd.Feeder) (*BPFEnforcer, error) {

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
		PinPath: pinpath,
	})
	if err != nil {
		be.Logger.Errf("error creating kubearmor_containers map: %s", err)
		return be, err
	}

	if err := loadEnforcerObjects(&be.obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
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

	be.Probes[be.obj.EnforceNetCreate.String()], err = link.AttachLSM(link.LSMOptions{Program: be.obj.EnforceNetCreate})
	if err != nil {
		be.Logger.Errf("opening lsm %s: %s", be.obj.EnforceNetCreate.String(), err)
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

	/*
		Path Hooks

		Create, Link, Unlink, Symlink, Rename, MkDir, RmDir, Chowm, Chmod, Truncate

		These will only work if the system has `CONFIG_SECURITY_PATH=y`

		We only warn if we fail to load the following hooks
	*/

	if err := loadEnforcer_pathObjects(&be.objPath, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: common.GetMapRoot(),
		},
	}); err != nil {
		be.Logger.Warnf("error loading BPF LSM Path objects. This usually suggests that the system doesn't have the system has `CONFIG_SECURITY_PATH=y`: %v", err)
	} else {
		be.Probes[be.objPath.EnforceMknod.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceMknod})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceMknod.String(), err)
		}

		be.Probes[be.objPath.EnforceLinkSrc.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceLinkSrc})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceLinkSrc.String(), err)
		}

		be.Probes[be.objPath.EnforceLinkDst.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceLinkDst})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceLinkDst.String(), err)
		}

		be.Probes[be.objPath.EnforceUnlink.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceUnlink})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceUnlink.String(), err)
		}

		be.Probes[be.objPath.EnforceSymlink.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceSymlink})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceSymlink.String(), err)
		}

		be.Probes[be.objPath.EnforceMkdir.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceMkdir})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceMkdir.String(), err)
		}

		be.Probes[be.objPath.EnforceChmod.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceChmod})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceChmod.String(), err)
		}

		// We do not support Chown for now because of limitations of bpf_trampoline https://github.com/iovisor/bcc/issues/3657
		// be.Probes[be.objPath.EnforceChown.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceChown})
		// if err != nil {
		// 	be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceChown.String(), err)
		// }

		be.Probes[be.objPath.EnforceTruncate.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceTruncate})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceTruncate.String(), err)
		}

		be.Probes[be.objPath.EnforceRenameNew.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceRenameNew})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceRenameNew.String(), err)
		}

		be.Probes[be.objPath.EnforceRenameOld.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceRenameOld})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceRenameOld.String(), err)
		}

		be.Probes[be.objPath.EnforceRmdir.String()], err = link.AttachLSM(link.LSMOptions{Program: be.objPath.EnforceRmdir})
		if err != nil {
			be.Logger.Warnf("opening lsm %s: %s", be.objPath.EnforceRmdir.String(), err)
		}
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
		if link == nil {
			continue
		}
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
