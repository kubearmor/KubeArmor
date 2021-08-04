// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package eventAuditor

import (
	"errors"
	"fmt"
	"path/filepath"

	lbpf "github.com/aquasecurity/libbpfgo"
)

// =========================== //
// == Shared Map Management == //
// =========================== //

var sharedMaps = map[string]*lbpf.BPFMap{}
var sharedMapsNames = [...]string{"ka_ea_proc_spec_map"}
var pinBasePath = "/sys/fs/bpf/"

// pinMap Function
func pinMap(m *lbpf.BPFMap) error {
	return m.Pin(pinBasePath + m.GetName())
}

// unpinMap Function
func unpinMap(m *lbpf.BPFMap) error {
	return m.Unpin(pinBasePath + m.GetName())
}

// InitSharedMaps Function
func (ea *EventAuditor) InitSharedMaps() error {
	if len(sharedMaps) > 0 {
		return errors.New("sharedMaps is already initialized")
	}

	for _, mapName := range sharedMapsNames {
		var mapObjFilePath string
		var bpfMod *lbpf.Module
		var bpfMap *lbpf.BPFMap
		var err error

		mapObjFilePath, err = filepath.Abs("./output/" + mapName + ".o")
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
			continue
		}

		bpfMod, err = lbpf.NewModuleFromFile(mapObjFilePath)
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
			continue
		}

		err = bpfMod.BPFLoadObject()
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
			bpfMod.Close()
		}

		bpfMap, err = bpfMod.GetMap(mapName)
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
			bpfMod.Close()
		}

		err = pinMap(bpfMap)
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
		}

		sharedMaps[mapName] = bpfMap
	}

	if len(sharedMaps) < len(sharedMapsNames) {
		return fmt.Errorf("Only %d of %d maps correctly initialized",
			len(sharedMaps), len(sharedMapsNames))
	}

	return nil
}

// StopSharedMaps Function
func (ea *EventAuditor) StopSharedMaps() error {
	if len(sharedMaps) == 0 {
		return errors.New("There are no sharedMaps to stop")
	}

	var errOnStopping = map[string]int{}
	var err error

	for _, mapName := range sharedMapsNames {
		var bpfMap *lbpf.BPFMap
		var found bool

		if bpfMap, found = sharedMaps[mapName]; !found {
			errOnStopping[mapName]++
			ea.LogFeeder.Printf("Map %s is not initialized to be stopped", mapName)
			continue
		}

		err = unpinMap(bpfMap)
		if err != nil {
			errOnStopping[mapName]++
			ea.LogFeeder.Print(err.Error())
		}

		bpfMap.GetModule().Close()

		delete(sharedMaps, mapName)
	}

	if len(errOnStopping) > 0 {
		return fmt.Errorf("%d map(s) not correctly stopped", len(errOnStopping))
	}

	return nil
}

// handle process-spec table
