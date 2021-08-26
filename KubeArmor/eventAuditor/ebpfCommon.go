// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"errors"
	"os"
	"path/filepath"
)

// BPFObjRelPath constant
const BPFObjRelPath = "./BPF/objs/"
const pinBasePath = "/sys/fs/bpf/"

var bpfObjAbsPath string

// SetBPFObjPath Function
func (ea *EventAuditor) SetBPFObjPath(path string) error {
	var err error

	bpfObjAbsPath, err = filepath.Abs(path)
	if err != nil {
		return err
	}

	_, err = os.Stat(bpfObjAbsPath)
	if errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}
