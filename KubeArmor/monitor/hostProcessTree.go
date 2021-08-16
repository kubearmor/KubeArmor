// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ================== //
// == Process Tree == //
// ================== //

// AddActiveHostPid Function
func (mon *SystemMonitor) AddActiveHostPid(hostPid uint32, node tp.PidNode) {
	ActiveHostMap := *(mon.ActiveHostMap)
	ActiveHostMapLock := *(mon.ActiveHostMapLock)

	ActiveHostMapLock.Lock()
	defer ActiveHostMapLock.Unlock()

	// add pid node to ActiveHostMap
	if pidMap, ok := ActiveHostMap[hostPid]; ok {
		pidMap[hostPid] = node
	} else {
		newPidMap := tp.PidMap{node.HostPID: node}
		ActiveHostMap[hostPid] = newPidMap
	}
}

// GetHostExecPath Function
func (mon *SystemMonitor) GetHostExecPath(hostPid uint32) string {
	ActiveHostMap := *(mon.ActiveHostMap)
	ActiveHostMapLock := *(mon.ActiveHostMapLock)

	ActiveHostMapLock.RLock()
	defer ActiveHostMapLock.RUnlock()

	if pidMap, ok := ActiveHostMap[hostPid]; ok {
		if node, ok := pidMap[hostPid]; ok {
			return node.ExecPath
		}
	}

	return ""
}

// DeleteActiveHostPid Function
func (mon *SystemMonitor) DeleteActiveHostPid(hostPid uint32) {
	ActiveHostMap := *(mon.ActiveHostMap)
	ActiveHostMapLock := *(mon.ActiveHostMapLock)

	ActiveHostMapLock.Lock()
	defer ActiveHostMapLock.Unlock()

	// delete execve(at) host pid
	if pidMap, ok := ActiveHostMap[hostPid]; ok {
		if node, ok := pidMap[hostPid]; ok {
			node.Exited = true
			node.ExitedTime = time.Now()
		}
	}
}
