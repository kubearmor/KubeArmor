package eventAuditor

import (
	"errors"
	"os"
	"path/filepath"

	lbpf "github.com/aquasecurity/tracee/libbpfgo"
)

// =========================== //
// == Shared Map Management == //
// =========================== //

var sharedMapNames = [...]string{"ka_ea_proc_spec_map"}
var sharedMaps map[string]*lbpf.BPFMap

func pinMap(m *lbpf.BPFMap, mapName string) (err error) {
	pinPath := "/sys/fs/bpf/" + mapName

	_, err = os.Stat(pinPath)
	if os.IsNotExist(err) {
		// not pinned
		err = m.Pin(pinPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (ea *EventAuditor) InitSharedMaps() (err error) {
	if len(sharedMaps) > 0 {
		return errors.New("sharedMaps is already initialized")
	}

	for _, mapName := range sharedMapNames {
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

		sharedMaps[mapName] = bpfMap
	}

	return nil
}

// handle process-spec table
