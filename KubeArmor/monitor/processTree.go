// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package monitor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ============================ //
// == PID-to-ContainerID Map == //
// ============================ //

// LookupContainerID Function
func (mon *SystemMonitor) LookupContainerID(pidns, mntns uint32) string {
	key := NsKey{PidNS: pidns, MntNS: mntns}

	mon.NsMapLock.RLock()
	defer mon.NsMapLock.RUnlock()

	if val, ok := mon.NsMap[key]; ok {
		return val
	}

	return ""
}

// AddContainerIDToNsMap Function
func (mon *SystemMonitor) AddContainerIDToNsMap(containerID string, namespace string, pidns, mntns uint32) {
	key := NsKey{PidNS: pidns, MntNS: mntns}

	mon.NsMapLock.Lock()
	mon.NsMap[key] = containerID
	mon.NsMapLock.Unlock()

	mon.BpfMapLock.Lock()
	if val, ok := mon.NamespacePidsMap[namespace]; ok {
		// check if nskey already exist
		found := false
		for i := range val.NsKeys {
			if val.NsKeys[i].MntNS == mntns && val.NsKeys[i].PidNS == pidns {
				found = true
				break
			}
		}

		if !found {
			val.NsKeys = append(val.NsKeys, key)
			mon.NamespacePidsMap[namespace] = val
			mon.UpdateNsKeyMap("ADDED", key, tp.Visibility{
				File:         val.File,
				Process:      val.Process,
				Capabilities: val.Capability,
				Network:      val.Network,
				DNS:          val.DNS,
			})
		}
	} else {
		mon.NamespacePidsMap[namespace] = NsVisibility{
			NsKeys: []NsKey{
				key,
			},
		}
		// Set Visibility to Global Default
		visibility := tp.Visibility{
			File:         strings.Contains(cfg.GlobalCfg.Visibility, "file"),
			Process:      strings.Contains(cfg.GlobalCfg.Visibility, "process"),
			Network:      strings.Contains(cfg.GlobalCfg.Visibility, "network"),
			Capabilities: strings.Contains(cfg.GlobalCfg.Visibility, "capabilities"),
			DNS:          strings.Contains(cfg.GlobalCfg.Visibility, "dns"),
		}
		mon.UpdateNsKeyMap("ADDED", key, visibility)
	}
	mon.BpfMapLock.Unlock()
}

// DeleteContainerIDFromNsMap Function
func (mon *SystemMonitor) DeleteContainerIDFromNsMap(containerID string, namespace string, pidns, mntns uint32) {
	ns := NsKey{
		PidNS: pidns,
		MntNS: mntns,
	}

	found := true
	mon.NsMapLock.Lock()
	if pidns != 0 && mntns != 0 {
		delete(mon.NsMap, ns)
	} else {
		found = false
		for key, val := range mon.NsMap {
			if containerID == val {
				ns = key
				found = true
				break
			}
		}
	}
	mon.NsMapLock.Unlock()

	if !found {
		return
	}

	mon.BpfMapLock.Lock()
	defer mon.BpfMapLock.Unlock()
	if val, ok := mon.NamespacePidsMap[namespace]; ok {
		for i := range val.NsKeys {
			if val.NsKeys[i].MntNS == ns.MntNS && val.NsKeys[i].PidNS == ns.PidNS {
				val.NsKeys = append(val.NsKeys[:i], val.NsKeys[i+1:]...)
				break
			}
		}
		mon.NamespacePidsMap[namespace] = val
		mon.UpdateNsKeyMap("DELETED", ns, tp.Visibility{})
	}
}

// ================== //
// == Process Tree == //
// ================== //

// BuildPidNode Function
func (mon *SystemMonitor) BuildPidNode(containerID string, ctx SyscallContext, execPath string, args []string, lock bool) tp.PidNode {
	node := tp.PidNode{}

	node.HostPPID = ctx.HostPPID
	node.HostPID = ctx.HostPID

	node.PPID = ctx.PPID
	node.PID = ctx.PID
	node.UID = ctx.UID

	node.ParentExecPath = mon.GetParentExecPath(containerID, ctx, false, lock)
	node.ExecPath = execPath

	node.Source = execPath
	node.Args = ""

	for idx, arg := range args {
		if idx == 0 {
			continue
		} else if idx == 1 {
			node.Args = arg
		} else {
			node.Args = node.Args + " " + arg
		}
	}

	node.Exited = false

	return node
}

// AddActivePid Function
func (mon *SystemMonitor) AddActivePid(containerID string, node tp.PidNode) {
	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	// add pid node to ActiveHostPidMap
	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		pidMap[node.HostPID] = node
	} else {
		newPidMap := tp.PidMap{node.HostPID: node}
		ActiveHostPidMap[containerID] = newPidMap
	}
}

// UpdateExecPath Function
func (mon *SystemMonitor) UpdateExecPath(containerID string, hostPid uint32, execPath string) {
	if execPath == "/" || !strings.HasPrefix(execPath, "/") {
		return
	}

	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[hostPid]; ok && node.ExecPath != execPath {
			originalPath := strings.Replace(node.Source, "./", "", 1)
			if strings.Contains(execPath, originalPath) {
				newNode := node
				newNode.Source = execPath   // full path
				newNode.ExecPath = execPath // full path
				ActiveHostPidMap[containerID][hostPid] = newNode
			} else {
				newNode := node
				newNode.ExecPath = execPath // full path
				ActiveHostPidMap[containerID][hostPid] = newNode
			}
		}
	}
}

// GetParentExecPath Function
func (mon *SystemMonitor) GetParentExecPath(containerID string, ctx SyscallContext, readlink bool, lock bool) string {
	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)
	if !lock {
		ActivePidMapLock.Lock()
		defer ActivePidMapLock.Unlock()
	}

	path := ""

	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[ctx.HostPID]; ok {
			path = node.ParentExecPath
			if path != "/" && strings.HasPrefix(path, "/") {
				return path
			}
		}
		// check if parent pid node exists
		if node, ok := pidMap[ctx.HostPPID]; ok {
			path = node.ExecPath
			if path != "/" && strings.HasPrefix(path, "/") {
				return path
			}
		}
	}

	if readlink {
		// just in case that it couldn't still get the full path
		if data, err := os.Readlink(filepath.Join(cfg.GlobalCfg.ProcFsMount, strconv.FormatUint(uint64(ctx.HostPPID), 10), "/exe")); err == nil && data != "" && data != "/" {
			// // Store it in the ActiveHostPidMap so we don't need to read procfs again
			// // We don't call BuildPidNode Here cause that will put this into a cyclic function call loop
			if pidMap, ok := ActiveHostPidMap[containerID]; ok {
				if node, ok := pidMap[ctx.HostPPID]; ok {
					node.ExecPath = data
					pidMap[ctx.HostPPID] = node
				} else if node, ok := pidMap[ctx.HostPID]; ok {
					node.ParentExecPath = data
					pidMap[ctx.HostPID] = node
				}
			}
			return data
		} else if err != nil {
			mon.Logger.Debugf("Could not read path from procfs due to %s", err.Error())
		} else {
			mon.Logger.Debugf("Could not read path from procfs due to unknown error")
		}
	}

	// return non full path
	return path
}

// GetExecPath Function
func (mon *SystemMonitor) GetExecPath(containerID string, ctx SyscallContext, readlink bool) string {
	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	path := ""

	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[ctx.HostPID]; ok {
			path = node.ExecPath
			if path != "/" && strings.HasPrefix(path, "/") {
				return path
			}
		}
	}

	if readlink {
		// just in case that it couldn't still get the full path
		if data, err := os.Readlink(filepath.Join(cfg.GlobalCfg.ProcFsMount, strconv.FormatUint(uint64(ctx.HostPID), 10), "/exe")); err == nil && data != "" && data != "/" {
			// // Store it in the ActiveHostPidMap so we don't need to read procfs again
			if pidMap, ok := ActiveHostPidMap[containerID]; ok {
				if node, ok := pidMap[ctx.HostPID]; ok {
					node.ExecPath = data
					pidMap[ctx.HostPID] = node
				} else {
					newPidNode := mon.BuildPidNode(containerID, ctx, data, []string{}, true)
					pidMap[ctx.HostPID] = newPidNode
				}
			}
			return data
		} else if err != nil {
			mon.Logger.Debugf("Could not read path from procfs due to %s", err.Error())
		} else {
			mon.Logger.Debugf("Could not read path from procfs due to an unknown error")
		}
	}

	// return non full path
	return path
}

// GetCommand Function
func (mon *SystemMonitor) GetCommand(containerID string, ctx SyscallContext, readlink bool) string {
	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[ctx.HostPID]; ok {
			if node.Args != "" {
				return node.Source + " " + node.Args
			}
			return node.Source
		}
	}

	if readlink {
		// just in case that it couldn't still get the full path
		if data, err := os.Readlink(filepath.Join(cfg.GlobalCfg.ProcFsMount, strconv.FormatUint(uint64(ctx.HostPID), 10), "/exe")); err == nil && data != "" && data != "/" {
			return data
		} else if err != nil {
			mon.Logger.Debugf("Could not read path from procfs due to %s", err.Error())
		} else {
			mon.Logger.Debugf("Could not read path from procfs due to an unknown error")
		}
	}

	return ""
}

// DeleteActivePid Function
func (mon *SystemMonitor) DeleteActivePid(containerID string, ctx SyscallContext) {
	now := time.Now()

	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	// delete execve(at) host pid
	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[ctx.HostPID]; ok {
			newNode := node
			newNode.Exited = true
			newNode.ExitedTime = now
			pidMap[ctx.HostPID] = newNode
		}
	}
}

func cleanMaps(pidMap tp.PidMap, execLogMap map[uint32]tp.Log, execLogMapLock *sync.RWMutex, pid uint32) {
	delete(pidMap, pid)
	execLogMapLock.Lock()
	delete(execLogMap, pid)
	execLogMapLock.Unlock()
}

// CleanUpExitedHostPids Function
func (mon *SystemMonitor) CleanUpExitedHostPids() {
	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)
	MonitorLock := *(mon.MonitorLock)

	for {
		now := time.Now()

		ActivePidMapLock.Lock()

		for containerID, pidMap := range ActiveHostPidMap {
			for pid, pidNode := range pidMap {
				if pidNode.Exited && now.After(pidNode.ExitedTime.Add(time.Second*5)) {
					cleanMaps(pidMap, mon.execLogMap, mon.execLogMapLock, pid)
				} else if now.After(pidNode.ExitedTime.Add(time.Second * 30)) {
					p, err := os.FindProcess(int(pid))
					if err == nil && p != nil {
						if p.Signal(syscall.Signal(0)) != nil {
							cleanMaps(pidMap, mon.execLogMap, mon.execLogMapLock, pid)
						}
					} else {
						cleanMaps(pidMap, mon.execLogMap, mon.execLogMapLock, pid)
					}
				}
			}

			if len(pidMap) == 0 {
				delete(ActiveHostPidMap, containerID)
			}
		}

		ActivePidMapLock.Unlock()

		// read monitor status
		MonitorLock.RLock()
		monStatus := mon.Status
		MonitorLock.RUnlock()

		if !monStatus {
			break
		}

		time.Sleep(10 * time.Second)
	}

}
