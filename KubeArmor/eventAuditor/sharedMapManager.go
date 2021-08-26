// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package eventauditor

import (
	"errors"
	"fmt"
	"os"
	"path"

	lbpf "github.com/kubearmor/libbpf"
)

// =========================== //
// == Shared Map Management == //
// =========================== //

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

// initSharedMap Function
func initSharedMap(mapName string) (*lbpf.KABPFMap, error) {
	var mapObjFilePath string
	var bpfObj *lbpf.KABPFObject
	var bpfMap *lbpf.KABPFMap
	var err error

	mapObjFilePath = path.Join(bpfObjAbsPath, mapName+".bpf.o")

	_, err = os.Stat(mapObjFilePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	bpfObj, err = lbpf.OpenObjectFromFile(mapObjFilePath)
	if err != nil {
		return nil, err
	}

	err = bpfObj.Load()
	if err != nil {
		bpfObj.Close()
		return nil, err
	}

	bpfMap, err = bpfObj.FindMapByName(mapName)
	if err != nil {
		bpfObj.Close()
		return nil, err
	}

	err = pinMap(bpfMap)
	if err != nil {
		bpfObj.Close()
		return nil, err
	}

	return bpfMap, nil
}

// InitSharedMaps Function
func (ea *EventAuditor) InitSharedMaps() error {
	if len(sharedMaps) > 0 {
		return errors.New("Shared maps are already initialized")
	}

	var errOnInitializing []string

	for _, mapName := range sharedMapsNames {
		var bpfMap *lbpf.KABPFMap
		var err error

		bpfMap, err = initSharedMap(mapName)
		if err != nil {
			errOnInitializing = append(errOnInitializing, mapName)
			continue
		}

		sharedMaps[mapName] = bpfMap
	}

	if len(errOnInitializing) > 0 {
		return fmt.Errorf("%d map(s) not correctly initialized: %v",
			len(errOnInitializing), errOnInitializing)
	}

	return nil
}

// StopSharedMaps Function
func (ea *EventAuditor) StopSharedMaps() error {
	if len(sharedMaps) == 0 {
		return errors.New("There are no shared maps to stop")
	}

	var errOnStopping []string

	for _, bpfMap := range sharedMaps {
		var err error

		mapName := bpfMap.Name()

		err = unpinMap(bpfMap)
		if err != nil {
			errOnStopping = append(errOnStopping, mapName)
		}

		bpfMap.Object().Close()

		delete(sharedMaps, mapName)
	}

	if len(errOnStopping) > 0 {
		return fmt.Errorf("%d map(s) not correctly stopped: %v",
			len(errOnStopping), errOnStopping)
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
