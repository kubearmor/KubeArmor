// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package monitor

import (
	"os"
	"strconv"
	"strings"
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ============================ //
// == PID-to-ContainerID Map == //
// ============================ //

// LookupContainerID Function
func (mon *SystemMonitor) LookupContainerID(pidns, mntns, ppid, pid uint32) string {
	key := NsKey{PidNS: pidns, MntNS: mntns}

	mon.NsMapLock.RLock()
	defer mon.NsMapLock.RUnlock()

	if val, ok := mon.NsMap[key]; ok {
		return val
	}

	return ""
}

// AddContainerIDToNsMap Function
func (mon *SystemMonitor) AddContainerIDToNsMap(containerID string, pidns, mntns uint32) {
	key := NsKey{PidNS: pidns, MntNS: mntns}

	mon.NsMapLock.Lock()
	defer mon.NsMapLock.Unlock()

	mon.NsMap[key] = containerID
}

// DeleteContainerIDFromNsMap Function
func (mon *SystemMonitor) DeleteContainerIDFromNsMap(containerID string) {
	ns := NsKey{}

	mon.NsMapLock.Lock()
	defer mon.NsMapLock.Unlock()

	for key, val := range mon.NsMap {
		if containerID == val {
			ns = key
			break
		}
	}

	if ns.PidNS != 0 && ns.MntNS != 0 {
		delete(mon.NsMap, ns)
	}
}

// ================== //
// == Process Tree == //
// ================== //

// BuildPidNode Function
func (mon *SystemMonitor) BuildPidNode(containerID string, ctx SyscallContext, execPath string, args []string) tp.PidNode {
	node := tp.PidNode{}

	node.HostPPID = ctx.HostPPID
	node.HostPID = ctx.HostPID

	node.PPID = ctx.PPID
	node.PID = ctx.PID
	node.UID = ctx.UID

	node.ParentExecPath = mon.GetExecPath(containerID, ctx.HostPPID)
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

// GetExecPath Function
func (mon *SystemMonitor) GetExecPath(containerID string, hostPid uint32) string {
	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[hostPid]; ok {
			if node.ExecPath != "/" && strings.HasPrefix(node.ExecPath, "/") {
				return node.ExecPath
			}
		}
	}

	// just in case that it couldn't still get the full path
	if data, err := os.Readlink("/proc/" + strconv.FormatUint(uint64(hostPid), 10) + "/exe"); err == nil && data != "" && data != "/" {
		return data
	}

	return ""
}

// GetCommand Function
func (mon *SystemMonitor) GetCommand(containerID string, hostPid uint32) string {
	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[hostPid]; ok {
			if node.Args != "" {
				return node.Source + " " + node.Args
			}
			return node.Source
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
			node.Exited = true
			node.ExitedTime = now
		}
	}
}

// CleanUpExitedHostPids Function
func (mon *SystemMonitor) CleanUpExitedHostPids() {
	for range mon.Ticker.C {
		now := time.Now()

		ActiveHostPidMap := *(mon.ActiveHostPidMap)
		ActivePidMapLock := *(mon.ActivePidMapLock)

		ActivePidMapLock.Lock()

		for _, pidMap := range ActiveHostPidMap {
			for pid, pidNode := range pidMap {
				if pidNode.Exited {
					if now.After(pidNode.ExitedTime.Add(time.Second * 5)) {
						delete(pidMap, pid)
					}
				}
			}
		}

		ActivePidMapLock.Unlock()
	}
}
