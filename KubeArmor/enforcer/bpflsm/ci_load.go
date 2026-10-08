// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build linux

package bpflsm

import (
	"errors"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestCILoad() {

	log.Println("Initializing BPF-LSM Enforcer")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("error removing memlock %v", err)
	}

	pinPath := "/sys/fs/bpf/kubearmor_ci_test"
	if err := os.MkdirAll(pinPath, 0750); err != nil {
		log.Fatalf("failed to create bpf pin path: %v", err)
	}
	defer os.RemoveAll(pinPath)

	innerMapSpec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    400,
		ValueSize:  4,
		MaxEntries: 256,
	}

	bpfContainerMap, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.HashOfMaps,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 256,
		Pinning:    ebpf.PinByName,
		InnerMap:   innerMapSpec,
		Name:       "kubearmor_containers",
	}, ebpf.MapOptions{
		PinPath: pinPath,
	})
	if err != nil {
		log.Fatalf("error creating kubearmor_containers map: %s", err)
	}
	defer bpfContainerMap.Unpin()
	defer bpfContainerMap.Close()

	bpfContainerThrottleMap, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  24,
		MaxEntries: 256,
		Pinning:    ebpf.PinByName,
		Name:       "kubearmor_alert_throttle",
	}, ebpf.MapOptions{
		PinPath: pinPath,
	})
	if err != nil {
		log.Fatalf("error creating kubearmor_alert_throttle map: %s", err)
	}
	defer bpfContainerThrottleMap.Unpin()
	defer bpfContainerThrottleMap.Close()

	bpfArgumentsMap, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    512,
		ValueSize:  1,
		MaxEntries: 10240,
		Name:       "kubearmor_arguments",
		Pinning:    ebpf.PinByName,
	}, ebpf.MapOptions{
		PinPath: pinPath,
	})
	if err != nil {
		log.Fatalf("error creating kubearmor_arguments_map: %s", err)
	}
	defer bpfArgumentsMap.Unpin()
	defer bpfArgumentsMap.Close()

	var obj enforcerObjects
	if err := loadEnforcerObjects(&obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Using %+v will print the whole verifier error, not just the last
			// few lines.
			log.Fatalf("Verifier error: %+v", ve)
		}
		log.Fatalf("error loading BPF LSM objects: %v", err)
	}
	defer obj.Close()

	var objPath enforcer_pathObjects
	if err := loadEnforcer_pathObjects(&objPath, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		log.Fatalf("error loading BPF LSM Path objects. This usually suggests that the system doesn't have the system has `CONFIG_SECURITY_PATH=y`: %v", err)
	}
	defer objPath.Close()

	log.Println("Initialized BPF-LSM Enforcer")
}
