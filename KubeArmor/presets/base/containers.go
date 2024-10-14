package base

import (
	"errors"
	"os"
	"sync"

	"github.com/cilium/ebpf"
)

// NsKey struct
type NsKey struct {
	PidNS uint32
	MntNS uint32
}

// ContainerVal struct
type ContainerVal struct {
	NsKey  NsKey
	Policy string
}

// Containers struct
type Containers struct {
	BPFContainerMap *ebpf.Map
	// ContainerID -> NsKey
	ContainerMap     map[string]ContainerVal
	ContainerMapLock *sync.RWMutex
}

// NewContainers func
func NewContainers(emap *ebpf.Map) *Containers {
	c := &Containers{}
	c.BPFContainerMap = emap
	c.ContainerMap = make(map[string]ContainerVal)
	c.ContainerMapLock = new(sync.RWMutex)

	return c
}

// AddContainerIDToMap function adds container to containers map
func (c *Containers) AddContainerIDToMap(containerID string, pidns, mntns uint32) {
	ckv := NsKey{PidNS: pidns, MntNS: mntns}
	c.ContainerMapLock.Lock()
	defer c.ContainerMapLock.Unlock()
	c.ContainerMap[containerID] = ContainerVal{NsKey: ckv}
}

// DeleteContainerIDFromMap function removed container from container map and subsequently
// from BPF Map as well returns error if failed
func (c *Containers) DeleteContainerIDFromMap(id string) error {
	c.ContainerMapLock.Lock()
	defer c.ContainerMapLock.Unlock()

	if val, ok := c.ContainerMap[id]; ok {
		if err := c.DeleteContainerIDFromBPFMap(val.NsKey); err != nil {
			return err
		}
		delete(c.ContainerMap, id)
	}
	return nil
}

// DeleteContainerIDFromBPFMap deletes the container from BPF map and returns error if failed
func (c *Containers) DeleteContainerIDFromBPFMap(ckv NsKey) error {
	if err := c.BPFContainerMap.Delete(ckv); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
