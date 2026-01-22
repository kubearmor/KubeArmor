// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
package monitor

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang ima_hash ../BPF/ima_hash.bpf.c -- -I/usr/include/ -O2 -g -fno-stack-protector

// ImaHash struct
type ImaHash struct {
	logger *fd.Feeder
	probes map[string]link.Link
	obj    ima_hashObjects
}

// NewImaHash func initializes and return an instance of ImaHash
func NewImaHash(logger *fd.Feeder, pinPath string) (*ImaHash, error) {
	ih := &ImaHash{}
	ih.logger = logger
	ih.probes = map[string]link.Link{}

	if err := rlimit.RemoveMemlock(); err != nil {
		ih.logger.Errf("Error removing rlimit %v", err)
		// Doesn't require clean up so not returning err
		return nil, nil
	}

	if err := loadIma_hashObjects(&ih.obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Using %+v will print the whole verifier error, not just the last
			// few lines.
			ih.logger.Errf("Verifier error: %+v", ve)
		}
		ih.logger.Errf("error loading IMA BPF LSM objects: %v", err)
		return nil, nil
	}
	var err error

	ih.probes[ih.obj.ImaBprmCheckSecurity.String()], err = link.AttachLSM(link.LSMOptions{
		Program: ih.obj.ImaBprmCheckSecurity,
	})
	if err != nil {
		ih.logger.Errf("opening lsm %s: %s", ih.obj.ImaBprmCheckSecurity.String(), err)
		return nil, nil
	}

	return ih, nil
}

// DestroyImaHash func cleanup ImaHash resources
func (ih *ImaHash) DestroyImaHash() error {
	if ih == nil {
		return nil
	}

	for _, ln := range ih.probes {
		if ln == nil {
			continue
		}
		if err := ln.Close(); err != nil {
			return err
		}
	}
	if err := ih.obj.Close(); err != nil {
		return err
	}
	return nil
}
