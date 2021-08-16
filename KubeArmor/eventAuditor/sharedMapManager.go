// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package eventauditor

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	lbpf "github.com/kubearmor/libbpf"
)

// =========================== //
// == Shared Map Management == //
// =========================== //

const BPFObjRelPath = "./BPF/objs/"
const pinBasePath = "/sys/fs/bpf/"

var bpfObjAbsPath string
var sharedMaps = map[string]*lbpf.KABPFMap{}
var sharedMapsNames = [...]string{
	KAEAPatternMap,
	KAEAProcessSpecMap,
	KAEAProcessFilterMap,
}

// pinMap Function
func pinMap(m *lbpf.KABPFMap) error {
	return m.Pin(pinBasePath + m.Name())
}

// unpinMap Function
func unpinMap(m *lbpf.KABPFMap) error {
	return m.Unpin(pinBasePath + m.Name())
}

// SetBPFObjPath Function
func (ea *EventAuditor) SetBPFObjPath(path string) {
	var err error

	bpfObjAbsPath, err = filepath.Abs(path)
	if err != nil {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(-1)
	}

	_, err = os.Stat(bpfObjAbsPath)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprint(os.Stderr, err.Error())
		os.Exit(-1)
	}
}

// InitSharedMaps Function
func (ea *EventAuditor) InitSharedMaps() error {
	if len(sharedMaps) > 0 {
		return errors.New("Shared maps are already initialized")
	}

	for _, mapName := range sharedMapsNames {
		var mapObjFilePath string
		var bpfObj *lbpf.KABPFObject
		var bpfMap *lbpf.KABPFMap
		var err error

		mapObjFilePath = path.Join(bpfObjAbsPath, mapName+".bpf.o")

		_, err = os.Stat(mapObjFilePath)
		if errors.Is(err, os.ErrNotExist) {
			ea.LogFeeder.Err(err.Error())
			continue
		}

		bpfObj, err = lbpf.OpenObjectFromFile(mapObjFilePath)
		if err != nil {
			ea.LogFeeder.Err(err.Error())
			continue
		}

		err = bpfObj.Load()
		if err != nil {
			ea.LogFeeder.Err(err.Error())
			bpfObj.Close()
		}

		bpfMap, err = bpfObj.FindMapByName(mapName)
		if err != nil {
			ea.LogFeeder.Err(err.Error())
			bpfObj.Close()
		}

		err = pinMap(bpfMap)
		if err != nil {
			ea.LogFeeder.Err(err.Error())
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
		return errors.New("There are no shared maps to stop")
	}

	var errOnStopping = map[string]int{}
	var err error

	for _, mapName := range sharedMapsNames {
		var bpfMap *lbpf.KABPFMap
		var found bool

		if bpfMap, found = sharedMaps[mapName]; !found {
			errOnStopping[mapName]++
			ea.LogFeeder.Errf("Map %s is not initialized to be stopped", mapName)
			continue
		}

		err = unpinMap(bpfMap)
		if err != nil {
			errOnStopping[mapName]++
			ea.LogFeeder.Err(err.Error())
		}

		bpfMap.Object().Close()

		delete(sharedMaps, mapName)
	}

	if len(errOnStopping) > 0 {
		return fmt.Errorf("%d map(s) not correctly stopped", len(errOnStopping))
	}

	return nil
}

// BPFMapUpdateElement Function
func (ea *EventAuditor) BPFMapUpdateElement(mapElem lbpf.KABPFMapElement) error {
	m, found := sharedMaps[mapElem.MapName()]
	if !found {
		return fmt.Errorf("%s not found in shared maps", mapElem.MapName())
	}

	return m.UpdateElement(mapElem)
}

// BPFMapLookupElement Function
func (ea *EventAuditor) BPFMapLookupElement(mapElem lbpf.KABPFMapElement) ([]byte, error) {
	m, found := sharedMaps[mapElem.MapName()]
	if !found {
		return nil, fmt.Errorf("%s not found in shared maps", mapElem.MapName())
	}

	return m.LookupElement(mapElem)
}

// BPFMapDeleteElement Function
func (ea *EventAuditor) BPFMapDeleteElement(mapElem lbpf.KABPFMapElement) error {
	m, found := sharedMaps[mapElem.MapName()]
	if !found {
		return fmt.Errorf("%s not found in shared maps", mapElem.MapName())
	}

	return m.DeleteElement(mapElem)
}
