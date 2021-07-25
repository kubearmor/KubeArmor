package eventAuditor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	lbpf "github.com/aquasecurity/tracee/libbpfgo"
)

// =========================== //
// == Shared Map Management == //
// =========================== //

// eventAuditorEBPFModule Structure
type eventAuditorEBPFModule struct {
	eaMod *lbpf.Module
	eaMap *lbpf.BPFMap
}

var sharedMods = map[string]*eventAuditorEBPFModule{}
var sharedMapsNames = [...]string{"ka_ea_proc_spec_map"}
var pinBasePath = "/sys/fs/bpf/"

// pinMap Function
func pinMap(m *lbpf.BPFMap, mapName string) error {
	pinPath := pinBasePath + mapName

	_, err := os.Stat(pinPath)
	if errors.Is(err, os.ErrNotExist) {
		// not pinned
		err = m.Pin(pinPath)
	}

	return err
}

// unpinMap Function
func unpinMap(m *lbpf.BPFMap, mapName string) error {
	pinPath := pinBasePath + mapName

	_, err := os.Stat(pinPath)
	if err != nil {
		// pinned
		err = m.Unpin(pinPath)
	}

	return err
}

// InitSharedMaps Function
func (ea *EventAuditor) InitSharedMaps() error {
	if len(sharedMods) > 0 {
		return errors.New("sharedMods is already initialized")
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

		err = pinMap(bpfMap, mapName)
		if err != nil {
			ea.LogFeeder.Printf(err.Error())
		}

		sharedMods[mapName] = &eventAuditorEBPFModule{
			eaMod: bpfMod,
			eaMap: bpfMap,
		}
	}

	if len(sharedMods) < len(sharedMapsNames) {
		return fmt.Errorf("Only %d of %d maps correctly initialized",
			len(sharedMods), len(sharedMapsNames))
	}

	return nil
}

// StopSharedMaps Function
func (ea *EventAuditor) StopSharedMaps() error {
	if len(sharedMods) == 0 {
		return errors.New("There are no sharedMods to stop")
	}

	var errOnStopping = map[string]int{}
	var err error

	for _, mapName := range sharedMapsNames {
		var bpfMod *eventAuditorEBPFModule
		var found bool

		if bpfMod, found = sharedMods[mapName]; !found {
			errOnStopping[mapName]++
			ea.LogFeeder.Printf("Map %s is not initialized to be stopped", mapName)
			continue
		}

		err = unpinMap(bpfMod.eaMap, mapName)
		if err != nil {
			errOnStopping[mapName]++
			ea.LogFeeder.Print(err.Error())
		}

		bpfMod.eaMod.Close()

		delete(sharedMods, mapName)
	}

	if len(errOnStopping) > 0 {
		return fmt.Errorf("%d map(s) not correctly stopped", len(errOnStopping))
	}

	return nil
}

// handle process-spec table
