// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package eventauditor

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"syscall"

	lbpf "github.com/kubearmor/libbpf"
)

// KABPFManager Structure
type KABPFManager struct {
	objs          map[KABPFObjFileName]*lbpf.KABPFObject
	maps          map[KABPFMapName]*lbpf.KABPFMap
	progs         map[KABPFProgName]*lbpf.KABPFProgram
	links         map[KABPFEventName]*lbpf.KABPFLink
	objsMapsPath  string
	objsProgsPath string
}

// NewKABPFManager Fucntion
func NewKABPFManager() *KABPFManager {
	return &KABPFManager{
		objs:          map[KABPFObjFileName]*lbpf.KABPFObject{},
		maps:          map[KABPFMapName]*lbpf.KABPFMap{},
		progs:         map[KABPFProgName]*lbpf.KABPFProgram{},
		links:         map[KABPFEventName]*lbpf.KABPFLink{},
		objsMapsPath:  "",
		objsProgsPath: "",
	}
}

// SetObjsMapsPath Function
func (bm *KABPFManager) SetObjsMapsPath(path string) error {
	var validPath string
	var err error

	if validPath, err = validateObjsPath(path); err != nil {
		return err
	}

	bm.objsMapsPath = validPath

	return nil
}

// SetObjsProgsPath Function
func (bm *KABPFManager) SetObjsProgsPath(path string) error {
	var validPath string
	var err error

	if validPath, err = validateObjsPath(path); err != nil {
		return err
	}

	bm.objsProgsPath = validPath

	return nil
}

// InitMap Function
func (bm *KABPFManager) InitMap(kaMap KABPFMap, pin bool) error {
	var o *lbpf.KABPFObject
	var m *lbpf.KABPFMap
	var err error

	if m = bm.getMap(kaMap.Name); m != nil {
		return fmt.Errorf("map %v already initialized", kaMap.Name)
	}

	if o = bm.getObj(kaMap.FileName); o == nil {
		if o, err = openAndLoadObj(bm.objsMapsPath, kaMap.FileName); err != nil {
			return err
		}
	}

	if m, err = o.FindMapByName(string(kaMap.Name)); err != nil {
		bm.closeObjIfPossible(kaMap.FileName)
		return err
	}

	if pin {
		if err = pinMap(m); err != nil {
			bm.closeObjIfPossible(kaMap.FileName)
			return err
		}
	}

	bm.maps[kaMap.Name] = m
	bm.objs[kaMap.FileName] = o

	return nil
}

// DestroyMap Function
func (bm *KABPFManager) DestroyMap(kaMap KABPFMap) error {
	var m *lbpf.KABPFMap
	var err1, err2 error

	if m = bm.getMap(kaMap.Name); m == nil {
		return fmt.Errorf("map %v not initialized", kaMap.Name)
	}

	if m.IsPinned() {
		err1 = m.Unpin(m.PinPath())
	}

	if !bm.closeObjIfPossible(kaMap.FileName) {
		// this is a straightforward approach as kubearmor/libbpf
		// still does not support unloading specific maps
		err2 = syscall.Close(m.FD())
	}

	delete(bm.maps, kaMap.Name)

	return AppendErrors(err1, err2)
}

// InitProgram Function
func (bm *KABPFManager) InitProgram(kaProg KABPFProg) error {
	var o *lbpf.KABPFObject
	var p *lbpf.KABPFProgram
	var err error

	if p = bm.getProg(kaProg.Name); p != nil {
		return fmt.Errorf("program %v already initialized", kaProg.Name)
	}

	if o = bm.getObj(kaProg.FileName); o == nil {
		if o, err = openAndLoadObj(bm.objsProgsPath, kaProg.FileName); err != nil {
			return err
		}
	}

	if p, err = o.FindProgramByName(string(kaProg.Name)); err != nil {
		bm.closeObjIfPossible(kaProg.FileName)
		return err
	}

	bm.progs[kaProg.Name] = p
	bm.objs[kaProg.FileName] = o

	return nil
}

// DestroyProgram Function
func (bm *KABPFManager) DestroyProgram(kaProg KABPFProg) error {
	var p *lbpf.KABPFProgram

	if p = bm.getProg(kaProg.Name); p == nil {
		return fmt.Errorf("program %v not initialized", kaProg.Name)
	}

	if !bm.closeObjIfPossible(kaProg.FileName) {
		// this is a straightforward approach as kubearmor/libbpf
		// still does not support unloading specific programs
		if err := syscall.Close(p.FD()); err != nil {
			return err
		}
	}

	delete(bm.progs, kaProg.Name)

	return nil
}

// AttachProgram Function
func (bm *KABPFManager) AttachProgram(kaProg KABPFProg) error {
	var p *lbpf.KABPFProgram
	var l *lbpf.KABPFLink
	var err error

	if p = bm.getProg(kaProg.Name); p == nil {
		return fmt.Errorf("program %v not initialized", kaProg.Name)
	}

	if l = bm.getLink(kaProg.EventName); l != nil {
		return fmt.Errorf("program %v already attached to %v", kaProg.Name, kaProg.EventName)
	}

	switch kaProg.EventType {
	case lbpf.KABPFLinkTypeTracepoint:
		if l, err = p.AttachTracepoint(string(kaProg.EventName)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("undefined event type %v", kaProg.EventType)
	}

	bm.links[kaProg.EventName] = l

	return nil
}

// DetachProgram Function
func (bm *KABPFManager) DetachProgram(kaProg KABPFProg) error {
	var p *lbpf.KABPFProgram
	var l *lbpf.KABPFLink
	var err error

	if p = bm.getProg(kaProg.Name); p == nil {
		return fmt.Errorf("program %v not initialized", kaProg.Name)
	}

	if l = bm.getLink(kaProg.EventName); l == nil {
		return fmt.Errorf("program %v not attached to %v", kaProg.Name, kaProg.EventName)
	}

	// https://github.com/kubearmor/libbpf/issues/18
	if err = l.Detach(); err != nil {
		return err
	}

	delete(bm.links, kaProg.EventName)

	return err
}

// isObjCloseable Function
func (bm *KABPFManager) isObjCloseable(o *lbpf.KABPFObject) bool {
	if o == nil {
		return false
	}

	for _, m := range bm.maps {
		if o == m.Object() {
			return false
		}
	}

	for _, p := range bm.progs {
		if o == p.Object() {
			return false
		}
	}

	for _, l := range bm.links {
		if o == l.Program().Object() {
			return false
		}
	}

	return true
}

// closeObjIfPossible Function
func (bm *KABPFManager) closeObjIfPossible(n KABPFObjFileName) bool {
	o := bm.getObj(n)

	if !bm.isObjCloseable(o) {
		return false
	}

	o.Close()
	delete(bm.objs, n)

	return true
}

// MapUpdateElement Function
func (bm *KABPFManager) MapUpdateElement(e lbpf.KABPFMapElement) error {
	m := bm.getMap(KABPFMapName(e.MapName()))
	if m == nil {
		return fmt.Errorf("map %v not initialized", e.MapName())
	}

	return m.UpdateElement(e)
}

// MapLookupElement Function
func (bm *KABPFManager) MapLookupElement(e lbpf.KABPFMapElement) ([]byte, error) {
	m := bm.getMap(KABPFMapName(e.MapName()))
	if m == nil {
		return nil, fmt.Errorf("map %v not initialized", e.MapName())
	}

	return m.LookupElement(e)
}

// MapDeleteElement Function
func (bm *KABPFManager) MapDeleteElement(e lbpf.KABPFMapElement) error {
	m := bm.getMap(KABPFMapName(e.MapName()))
	if m == nil {
		return fmt.Errorf("map %v not initialized", e.MapName())
	}

	return m.DeleteElement(e)
}

// getObjFullPath Function
func getObjFullPath(objPath string, n KABPFObjFileName) (string, error) {
	objFilePath := path.Join(objPath, string(n))

	if _, err := os.Stat(objFilePath); err != nil {
		return "", err
	}

	return objFilePath, nil
}

// validateObjsPath Function
func validateObjsPath(path string) (string, error) {
	var absPath string
	var err error

	if absPath, err = filepath.Abs(path); err != nil {
		return "", err
	}

	if _, err = os.Stat(absPath); err != nil {
		return "", err
	}

	return absPath, nil
}

// openAndLoadObj Function
func openAndLoadObj(objsPath string, n KABPFObjFileName) (*lbpf.KABPFObject, error) {
	var objFilePath string
	var o *lbpf.KABPFObject
	var err error

	if objFilePath, err = getObjFullPath(objsPath, n); err != nil {
		return nil, err
	}

	if o, err = lbpf.OpenObjectFromFile(objFilePath); err != nil {
		return nil, err
	}

	if err = o.Load(); err != nil {
		return nil, err
	}

	return o, nil
}

// getObj Function
func (bm *KABPFManager) getObj(n KABPFObjFileName) *lbpf.KABPFObject {
	return bm.objs[n]
}

// getMap Function
func (bm *KABPFManager) getMap(n KABPFMapName) *lbpf.KABPFMap {
	return bm.maps[n]
}

// getProg Function
func (bm *KABPFManager) getProg(n KABPFProgName) *lbpf.KABPFProgram {
	return bm.progs[n]
}

// getLink Function
func (bm *KABPFManager) getLink(n KABPFEventName) *lbpf.KABPFLink {
	return bm.links[n]
}

// pinMap Function
func pinMap(m *lbpf.KABPFMap) error {
	return m.Pin(KABPFPinBasePath + m.Name())
}
