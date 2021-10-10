// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"errors"

	lbpf "github.com/kubearmor/libbpf"
)

// KABPFObjFileName type
type KABPFObjFileName string

// KABPFMapName type
type KABPFMapName string

// KABPFProgName type
type KABPFProgName string

// KABPFEventName type
type KABPFEventName string

// KABPFMap structure
type KABPFMap struct {
	Name     KABPFMapName
	FileName KABPFObjFileName
}

// KABPFProg structure
type KABPFProg struct {
	Name      KABPFProgName
	EventName KABPFEventName
	EventType lbpf.KABPFLinkType
	TailProgs []KABPFTailProg
	FileName  KABPFObjFileName
}

// KABPFTailProg structure
type KABPFTailProg struct {
	Name  KABPFProgName
	Index uint32
}

// KABPFPinBasePath constant
const KABPFPinBasePath = "/sys/fs/bpf/"

// AppendErrors Function
// To be moved to project common place or replaced for other solution
func AppendErrors(errs ...error) error {
	var es string

	for _, e := range errs {
		if e != nil {
			if len(es) > 0 {
				es += "; "
			}
			es += e.Error()
		}
	}

	if len(es) > 0 {
		return errors.New(es)
	}

	return nil
}
