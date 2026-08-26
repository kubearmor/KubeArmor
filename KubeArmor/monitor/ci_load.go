// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build ignore

package main

import (
	"errors"
	"log"
	"os"
	"path/filepath"

	cle "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	homeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("Failed to get the absolute path of the current directory: %v", err)
	}

	bpfPath := homeDir + "/BPF/"
	if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil { // #nosec G703 -- trusted
		// go test

		bpfPath = os.Getenv("PWD") + "/../BPF/"
		if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil { // #nosec G703 -- trusted path
			// container

			bpfPath = "/opt/kubearmor/BPF/"
			if _, err := os.Stat(filepath.Clean(bpfPath)); err != nil {
				log.Fatalf("BPF path not found: %s", bpfPath)
			}
		}
	}

	log.Println("Initializing eBPF system monitor")

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("error removing memlock %v", err)
	}

	bpfPath = bpfPath + "system_monitor.bpf.o"

	log.Printf("eBPF system monitor object file path: %s\n", bpfPath)
	bpfModuleSpec, err := cle.LoadCollectionSpec(bpfPath)
	if err != nil {
		log.Fatalf("cannot load bpf module specs %v", err)
	}

	innerMapSpec := &cle.MapSpec{
		Type:       cle.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 6,
	}

	if m, ok := bpfModuleSpec.Maps["kubearmor_visibility"]; ok {
		m.InnerMap = innerMapSpec
	}
	if m, ok := bpfModuleSpec.Maps["kubearmor_config"]; ok {
		m.InnerMap = innerMapSpec
	}

	pinPath := "/sys/fs/bpf/kubearmor_ci_test"
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf pin path: %v", err)
	}
	defer os.RemoveAll(pinPath)

	bpfModuleCol, err := cle.NewCollectionWithOptions(
		bpfModuleSpec,
		cle.CollectionOptions{
			Maps: cle.MapOptions{
				PinPath: pinPath,
			},
		},
	)
	if err != nil {
		var verr *cle.VerifierError
		if errors.As(err, &verr) {
			log.Printf("Full log: %+v\n", verr)
		}
		log.Fatalf("bpf module is nil %v", err)
	}
	defer bpfModuleCol.Close()

	log.Println("Initialized the eBPF system monitor")
}
