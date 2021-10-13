// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import "C"

import (
	"errors"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
)

// =========================== //
// == Entrypoint Management == //
// =========================== //

// InitializeEntryPoints Function
func (ea *EventAuditor) InitializeEntryPoints() bool {
	var err error

	if ea.BPFManager == nil {
		return false
	}

	if err = ea.BPFManager.InitMap(KAEAGetMap(KAEAEventMap), true); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEventMap: %v", err)
		return false
	}

	if err = ea.BPFManager.InitMap(KAEAGetMap(KAEAEventFilterMap), true); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEventFilterMap: %v", err)
		goto fail1
	}

	if err = ea.BPFManager.InitMap(KAEAGetMap(KAEAEventJumpTable), true); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEventJumpTable: %v", err)
		goto fail2
	}

	ea.SupportedEntryPoints = map[string]uint32{
		"execve": 59, "execveat": 322, "open": 2, "openat": 257,
		"socket": 41, "connect": 42, "accept": 43, "bind": 49, "listen": 50}

	ea.EntryPointParameters = make(map[string][]string)
	ea.EntryPointParameters["execve"] = []string{"Path"}
	ea.EntryPointParameters["execveat"] = []string{"Path", "Flags"}
	ea.EntryPointParameters["open"] = []string{"Path", "Flags", "Mode"}
	ea.EntryPointParameters["openat"] = []string{"Path", "Flags", "Mode"}
	ea.EntryPointParameters["socket"] = []string{"Protocol"}
	ea.EntryPointParameters["connect"] = []string{"Ipv4Addr", "Ipv6Addr", "Port"}
	ea.EntryPointParameters["accept"] = []string{"Ipv4Addr", "Ipv6Addr", "Port"}
	ea.EntryPointParameters["bind"] = []string{"Ipv4Addr", "Ipv6Addr", "Port"}
	ea.EntryPointParameters["listen"] = []string{}

	if err = ea.InitializeEntryPointPrograms(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEntryPointPrograms: %v", err)
		goto fail3
	}

	return true

fail3:
	_ = ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventJumpTable))

fail2:
	_ = ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventFilterMap))

fail1:
	return false
}

// DestroyEntryPoints Function
func (ea *EventAuditor) DestroyEntryPoints() bool {
	var err error

	if ea.BPFManager == nil {
		return false
	}

	if err = ea.DestroyEntryPointPrograms(ea.BPFManager); err != nil {
		ea.Logger.Errf("Failed to initialize KAEAEntryPointPrograms: %v", err)
	}

	if err = ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventJumpTable)); err != nil {
		ea.Logger.Errf("Failed to destroy KAEAEventJumpTable: %v", err)
	}

	if err = ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventFilterMap)); err != nil {
		ea.Logger.Errf("Failed to destroy KAEAEventFilterMap: %v", err)
	}

	if err = ea.BPFManager.DestroyMap(KAEAGetMap(KAEAEventMap)); err != nil {
		ea.Logger.Errf("Failed to destroy KAEAEventMap: %v", err)
	}

	return true
}

// InitializeEntryPointPrograms Function
func (ea *EventAuditor) InitializeEntryPointPrograms(bman *KABPFManager) error {
	if bman == nil {
		return errors.New("bpf manager cannot be nil")
	}

	for probe := range ea.SupportedEntryPoints {
		if err := bman.InitProgram(KAEAGetEntryPointProg(probe)); err != nil {
			return err
		}

		if err := bman.AttachProgram(KAEAGetEntryPointProg(probe)); err != nil {
			return err
		}

		ea.DisableEntryPoint(probe)
	}

	return nil
}

// DestroyEntryPointPrograms Function
func (ea *EventAuditor) DestroyEntryPointPrograms(bman *KABPFManager) error {
	if bman == nil {
		return errors.New("bpf manager cannot be nil")
	}

	for probe := range ea.SupportedEntryPoints {
		ea.DisableEntryPoint(probe)

		if err := bman.DetachProgram(KAEAGetEntryPointProg(probe)); err != nil {
			return err
		}

		if err := bman.DestroyProgram(KAEAGetEntryPointProg(probe)); err != nil {
			return err
		}
	}

	return nil
}

// EnableEntryPoint Function
func (ea *EventAuditor) EnableEntryPoint(probe string) {
	var eventMapElem EventElement

	// currently handling syscalls only
	if strings.HasPrefix(probe, "sys_") {
		probe = strings.Replace(probe, "sys_", "", -1)
	}

	_, supported := ea.SupportedEntryPoints[probe]
	if !supported {
		ea.Logger.Warnf("%s is currently not supported", probe)
		return
	}

	eventMapElem.SetKey(uint32(ea.SupportedEntryPoints[probe]))
	eventMapElem.SetValue(uint32(1))

	if err := ea.BPFManager.MapUpdateElement(&eventMapElem); err != nil {
		ea.Logger.Errf("Failed to update KAEAEventMap (attachEntryPoint, %s, %d) (%v)", probe, err)
	}
}

// DisableEntryPoint Function
func (ea *EventAuditor) DisableEntryPoint(probe string) {
	var eventMapElem EventElement

	// currently handling syscalls only
	if strings.HasPrefix(probe, "sys_") {
		probe = strings.Replace(probe, "sys_", "", -1)
	}

	_, supported := ea.SupportedEntryPoints[probe]
	if !supported {
		ea.Logger.Warnf("%s is currently not supported", probe)
		return
	}

	eventMapElem.SetKey(uint32(ea.SupportedEntryPoints[probe]))
	eventMapElem.SetValue(uint32(0))

	if err := ea.BPFManager.MapUpdateElement(&eventMapElem); err != nil {
		ea.Logger.Errf("Failed to update KAEAEventMap (DetachEntryPoint, %s, %d) (%v)", probe, err)
	}
}

// UpdateEntryPoints Function
func (ea *EventAuditor) UpdateEntryPoints() {
	AuditPolicies := *(ea.AuditPolicies)
	AuditPoliciesLock := *(ea.AuditPoliciesLock)

	AuditPoliciesLock.Lock()
	defer AuditPoliciesLock.Unlock()

	entrypointList := []string{}

	// all entrypoints list
	for _, policy := range AuditPolicies {
		for _, event := range policy.Events {
			if !kl.ContainsElement(entrypointList, event.Probe) {
				entrypointList = append(entrypointList, event.Probe)
			}
		}
	}

	newEntryPointList := []string{}

	// new entrypoints to be attached
	for _, newProbe := range entrypointList {
		if !kl.ContainsElement(ea.ActiveEntryPoints, newProbe) {
			newEntryPointList = append(newEntryPointList, newProbe)
		}
	}

	// update entrypoints
	for _, probe := range newEntryPointList {
		ea.EnableEntryPoint(probe)
	}

	oldEntrypointList := []string{}

	// old entrypoints to be detached
	for _, oldProbe := range ea.ActiveEntryPoints {
		if !kl.ContainsElement(entrypointList, oldProbe) {
			oldEntrypointList = append(oldEntrypointList, oldProbe)
		}
	}

	// update entrypoints
	for _, probe := range oldEntrypointList {
		ea.DisableEntryPoint(probe)
	}

	// replace old list with new list
	ea.ActiveEntryPoints = entrypointList
}
