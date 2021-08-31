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

// SharedMapManager structure
type SharedMapManager struct {
	sharedMaps    map[KASharedMap]*lbpf.KABPFMap
	bpfObjAbsPath string
}

func NewSharedMapManager() *SharedMapManager {
	return &SharedMapManager{
		sharedMaps:    map[KASharedMap]*lbpf.KABPFMap{},
		bpfObjAbsPath: "",
	}
}

// SetBPFObjPath Function
func (smm *SharedMapManager) SetBPFObjPath(dir string) error {
	var err error

	smm.bpfObjAbsPath, err = filepath.Abs(dir)
	if err != nil {
		return err
	}

	_, err = os.Stat(smm.bpfObjAbsPath)
	if err != nil {
		return err
	}

	return nil
}

// PinMap Function
func (smm *SharedMapManager) PinMap(m *lbpf.KABPFMap) error {
	return m.Pin(PinBasePath + m.Name())
}

// GetMap Function
func (smm *SharedMapManager) GetMap(sharedMap KASharedMap) (*lbpf.KABPFMap, error) {
	ret, found := smm.sharedMaps[sharedMap]

	if !found {
		return nil, fmt.Errorf("%v map not initialized", sharedMap)
	}

	return ret, nil
}

// InitMap Function
func (smm *SharedMapManager) InitMap(sharedMap KASharedMap, pin bool) (*lbpf.KABPFMap, error) {
	var mapObjFilePath string
	var bpfObj *lbpf.KABPFObject
	var bpfMap *lbpf.KABPFMap
	var err error

	bpfMap, err = smm.GetMap(sharedMap)
	if bpfMap != nil {
		return nil, fmt.Errorf("%v map already initialized", sharedMap)
	}

	mapName := string(sharedMap)

	mapObjFilePath = path.Join(smm.bpfObjAbsPath, mapName+".bpf.o")

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

	if pin {
		err = smm.PinMap(bpfMap)
		if err != nil {
			bpfObj.Close()
			return nil, err
		}
	}

	smm.sharedMaps[sharedMap] = bpfMap

	return bpfMap, nil
}

// Function DestroySharedMap
func (smm *SharedMapManager) DestroyMap(sharedMap KASharedMap) error {
	var bpfMap *lbpf.KABPFMap
	var err error

	bpfMap, err = smm.GetMap(sharedMap)
	if err != nil {
		return fmt.Errorf("%v map not initialized", sharedMap)
	}

	if bpfMap.IsPinned() {
		err = bpfMap.Unpin(bpfMap.PinPath())
	}
	bpfMap.Object().Close()

	delete(smm.sharedMaps, sharedMap)

	return err
}

// MapUpdateElement Function
func (smm *SharedMapManager) MapUpdateElement(mapElem lbpf.KABPFMapElement) error {
	m, err := smm.GetMap(KASharedMap(mapElem.MapName()))
	if err != nil {
		return fmt.Errorf("%s not found in shared maps", mapElem.MapName())
	}

	return m.UpdateElement(mapElem)
}

// MapLookupElement Function
func (smm *SharedMapManager) MapLookupElement(mapElem lbpf.KABPFMapElement) ([]byte, error) {
	m, err := smm.GetMap(KASharedMap(mapElem.MapName()))
	if err != nil {
		return nil, fmt.Errorf("%s not found in shared maps", mapElem.MapName())
	}

	return m.LookupElement(mapElem)
}

// MapDeleteElement Function
func (smm *SharedMapManager) MapDeleteElement(mapElem lbpf.KABPFMapElement) error {
	m, err := smm.GetMap(KASharedMap(mapElem.MapName()))
	if err != nil {
		return fmt.Errorf("%s not found in shared maps", mapElem.MapName())
	}

	return m.DeleteElement(mapElem)
}
