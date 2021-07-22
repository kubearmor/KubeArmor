// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ================ //
// == Map Lookup == //
// ================ //

// GetProcessInfoFromHostPid Function
func (adt *AuditLogger) GetProcessInfoFromHostPid(log tp.Log, hostPid uint32) tp.Log {
	ActiveHostPidMap := *(adt.ActiveHostPidMap)
	ActivePidMapLock := *(adt.ActivePidMapLock)

	ActivePidMapLock.RLock()
	defer ActivePidMapLock.RUnlock()

	for id, pidMap := range ActiveHostPidMap {
		if node, ok := pidMap[hostPid]; ok {
			log.ContainerID = id

			// log.HostPID is already assigned

			log.PPID = int32(node.PPID)
			log.PID = int32(node.PID)
			log.UID = int32(node.UID)

			break
		}
	}

	if log.PID == 0 {
		log.PPID = -1
		log.PID = -1
		log.UID = -1
	}

	return log
}

// GetContainerInfoFromContainerID Function
func (adt *AuditLogger) GetContainerInfoFromContainerID(log tp.Log, profileName string) tp.Log {
	Containers := *(adt.Containers)
	ContainersLock := *(adt.ContainersLock)

	ContainersLock.RLock()
	defer ContainersLock.RUnlock()

	if log.ContainerID != "" {
		if val, ok := Containers[log.ContainerID]; ok {
			log.NamespaceName = val.NamespaceName
			log.PodName = val.ContainerGroupName

			// ContainerID is already assigned
			log.ContainerName = val.ContainerName
		}
	} else {
		for _, container := range Containers {
			if strings.HasPrefix(profileName, container.AppArmorProfile) {
				log.NamespaceName = container.NamespaceName
				log.PodName = container.ContainerGroupName

				log.ContainerID = container.ContainerID
				log.ContainerName = container.ContainerName

				break
			}
		}
	}

	return log
}

// GetExecPath Function
func (adt *AuditLogger) GetExecPath(containerID string, pid uint32) string {
	ActivePidMap := *(adt.ActivePidMap)
	ActivePidMapLock := *(adt.ActivePidMapLock)

	ActivePidMapLock.RLock()
	defer ActivePidMapLock.RUnlock()

	if pidMap, ok := ActivePidMap[containerID]; ok {
		if node, ok := pidMap[pid]; ok {
			return node.ExecPath
		}
	}

	return ""
}

// UpdateSourceAndResource Function
func (adt *AuditLogger) UpdateSourceAndResource(log tp.Log, source, resource string) tp.Log {
	if log.Operation == "Process" {
		log.Source = adt.GetExecPath(log.ContainerID, uint32(log.PPID))
		if log.Source == "" {
			log.Source = source
		}

		log.Resource = adt.GetExecPath(log.ContainerID, uint32(log.PID))
		if log.Resource == "" {
			log.Resource = resource
		} else if !strings.HasPrefix(log.Resource, resource) {
			log.Resource = resource
		}
	} else { // File
		log.Source = adt.GetExecPath(log.ContainerID, uint32(log.PID))
		if log.Source == "" {
			log.Source = source
		}

		log.Resource = resource
	}

	return log
}

// GetHostProcessInfoFromHostPid Function
func (adt *AuditLogger) GetHostProcessInfoFromHostPid(log tp.Log, hostPid uint32) tp.Log {
	ActiveHostMap := *(adt.ActiveHostMap)
	ActiveHostMapLock := *(adt.ActiveHostMapLock)

	ActiveHostMapLock.RLock()
	defer ActiveHostMapLock.RUnlock()

	if pidMap, ok := ActiveHostMap[hostPid]; ok {
		if node, ok := pidMap[hostPid]; ok {
			log.PPID = int32(node.PPID)
			log.PID = int32(node.PID)
			log.UID = int32(node.UID)
		}
	}

	if log.PID == 0 {
		log.PPID = -1
		log.PID = int32(hostPid)
		log.UID = -1
	}

	return log
}

// GetHostExecPath Function
func (adt *AuditLogger) GetHostExecPath(hostPid uint32) string {
	ActiveHostMap := *(adt.ActiveHostMap)
	ActiveHostMapLock := *(adt.ActiveHostMapLock)

	ActiveHostMapLock.RLock()
	defer ActiveHostMapLock.RUnlock()

	if pidMap, ok := ActiveHostMap[hostPid]; ok {
		if node, ok := pidMap[hostPid]; ok {
			return node.ExecPath
		}
	}

	return ""
}

// UpdateHostSourceAndResource Function
func (adt *AuditLogger) UpdateHostSourceAndResource(log tp.Log, source, resource string) tp.Log {
	if log.Operation == "Process" {
		log.Source = adt.GetHostExecPath(uint32(log.PPID))
		if log.Source == "" {
			log.Source = source
		}

		log.Resource = adt.GetHostExecPath(uint32(log.PID))
		if log.Resource == "" {
			log.Resource = resource
		} else if !strings.HasPrefix(log.Resource, resource) {
			log.Resource = resource
		}
	} else { // File
		log.Source = adt.GetHostExecPath(uint32(log.PID))
		if log.Source == "" {
			log.Source = source
		}

		log.Resource = resource
	}

	return log
}
