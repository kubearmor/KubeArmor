// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package eventAuditor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	lbpf "github.com/kubearmor/libbpf"
)

// =========================== //
// == Shared Map Management == //
// =========================== //

var sharedMaps = map[string]*lbpf.KABPFMap{}
var sharedMapsNames = [...]string{"ka_ea_pattern_map", "ka_ea_process_spec_map", "ka_ea_process_filter_map"}
var pinBasePath = "/sys/fs/bpf/"

// pinMap Function
func pinMap(m *lbpf.KABPFMap) error {
	return m.Pin(pinBasePath + m.Name())
}

// unpinMap Function
func unpinMap(m *lbpf.KABPFMap) error {
	return m.Unpin(pinBasePath + m.Name())
}

// InitSharedMaps Function
func (ea *EventAuditor) InitSharedMaps() error {
	if len(sharedMaps) > 0 {
		return errors.New("sharedMaps is already initialized")
	}

	for _, mapName := range sharedMapsNames {
		var mapObjFilePath string
		var bpfObj *lbpf.KABPFObject
		var bpfMap *lbpf.KABPFMap
		var err error

		mapObjFilePath, err = filepath.Abs("./BPF/objs/" + mapName + ".o")
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
			continue
		}

		_, err = os.Stat(mapObjFilePath)
		if errors.Is(err, os.ErrNotExist) {
			ea.LogFeeder.Printf(err.Error())
			continue
		}

		bpfObj, err = lbpf.OpenObjectFromFile(mapObjFilePath)
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
			continue
		}

		err = bpfObj.Load()
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
			bpfObj.Close()
		}

		bpfMap, err = bpfObj.FindMapByName(mapName)
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
			bpfObj.Close()
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
		var bpfMap *lbpf.KABPFMap
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

		bpfMap.Object().Close()

		delete(sharedMaps, mapName)
	}

	if len(errOnStopping) > 0 {
		return fmt.Errorf("%d map(s) not correctly stopped", len(errOnStopping))
	}

	return nil
}

// handle process-spec table
