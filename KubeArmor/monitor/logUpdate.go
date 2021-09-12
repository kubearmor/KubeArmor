// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package monitor

import (
	"bytes"
	"fmt"
	"strconv"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ========== //
// == Logs == //
// ========== //

// UpdateContainerInfoByContainerID Function
func (mon *SystemMonitor) UpdateContainerInfoByContainerID(log tp.Log) tp.Log {
	Containers := *(mon.Containers)
	ContainersLock := *(mon.ContainersLock)

	ContainersLock.RLock()
	defer ContainersLock.RUnlock()

	if val, ok := Containers[log.ContainerID]; ok {
		// update container info
		log.NamespaceName = val.NamespaceName
		log.PodName = val.ContainerGroupName
		log.ContainerName = val.ContainerName

		// update policy flag
		log.PolicyEnabled = val.PolicyEnabled

		// update visibility flags
		log.ProcessVisibilityEnabled = val.ProcessVisibilityEnabled
		log.FileVisibilityEnabled = val.FileVisibilityEnabled
		log.NetworkVisibilityEnabled = val.NetworkVisibilityEnabled
		log.CapabilitiesVisibilityEnabled = val.CapabilitiesVisibilityEnabled
	}

	return log
}

// BuildLogBase Function
func (mon *SystemMonitor) BuildLogBase(msg ContextCombined) tp.Log {
	log := tp.Log{}

	timestamp, updatedTime := kl.GetDateTimeNow()

	log.Timestamp = timestamp
	log.UpdatedTime = updatedTime
	log.ContainerID = msg.ContainerID

	if log.ContainerID != "" {
		log = mon.UpdateContainerInfoByContainerID(log)
	}

	log.HostPID = int32(msg.ContextSys.HostPID)

	log.PPID = int32(msg.ContextSys.PPID)
	log.PID = int32(msg.ContextSys.PID)
	log.UID = int32(msg.ContextSys.UID)

	if msg.ContextSys.EventID == SysExecve || msg.ContextSys.EventID == SysExecveAt {
		log.Source = mon.GetExecPath(msg.ContainerID, msg.ContextSys.PPID)
	} else {
		log.Source = mon.GetExecPath(msg.ContainerID, msg.ContextSys.PID)
	}

	if log.Source == "" {
		log.Source = string(msg.ContextSys.Comm[:bytes.IndexByte(msg.ContextSys.Comm[:], 0)])
	}

	return log
}

// UpdateLogs Function
func (mon *SystemMonitor) UpdateLogs() {
	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-mon.ContextChan:
			if !valid {
				continue
			}

			// generate a log
			log := mon.BuildLogBase(msg)

			switch msg.ContextSys.EventID {
			case SysOpen:
				var fileName string
				var fileOpenFlags string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(string); ok {
						fileName = val
					}
					if val, ok := msg.ContextArgs[1].(string); ok {
						fileOpenFlags = val
					}
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID)) + " flags=" + fileOpenFlags

			case SysOpenAt:
				var fd string
				var fileName string
				var fileOpenFlags string

				if len(msg.ContextArgs) == 3 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := msg.ContextArgs[1].(string); ok {
						fileName = val
					}
					if val, ok := msg.ContextArgs[2].(string); ok {
						fileOpenFlags = val
					}
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd + " flags=" + fileOpenFlags

			case SysClose:
				var fd string

				if len(msg.ContextArgs) == 1 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
				}

				log.Operation = "File"
				log.Resource = ""
				log.Data = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

			case SysSocket: // domain, type, proto
				var sockDomain string
				var sockType string
				var sockProtocol string

				if len(msg.ContextArgs) == 3 {
					if val, ok := msg.ContextArgs[0].(string); ok {
						sockDomain = val
					}
					if val, ok := msg.ContextArgs[1].(string); ok {
						sockType = val
					}
					if val, ok := msg.ContextArgs[2].(int32); ok {
						sockProtocol = strconv.Itoa(int(val))
					}
				}

				log.Operation = "Network"
				log.Resource = "domain=" + sockDomain + " type=" + sockType + " protocol=" + sockProtocol
				log.Data = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID))

			case SysConnect: // fd, sockaddr
				var fd string
				var sockAddr map[string]string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := msg.ContextArgs[1].(map[string]string); ok {
						sockAddr = val
					}
				}

				log.Operation = "Network"
				log.Resource = ""

				for k, v := range sockAddr {
					if log.Resource == "" {
						log.Resource = k + "=" + v
					} else {
						log.Resource = log.Resource + " " + k + "=" + v
					}
				}

				log.Data = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

			case SysAccept: // fd, sockaddr
				var fd string
				var sockAddr map[string]string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := msg.ContextArgs[1].(map[string]string); ok {
						sockAddr = val
					}
				}

				log.Operation = "Network"
				log.Resource = ""
				log.Data = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

				for k, v := range sockAddr {
					if log.Resource == "" {
						log.Resource = k + "=" + v
					} else {
						log.Resource = log.Resource + " " + k + "=" + v
					}
				}

			case SysBind: // fd, sockaddr
				var fd string
				var sockAddr map[string]string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := msg.ContextArgs[1].(map[string]string); ok {
						sockAddr = val
					}
				}

				log.Operation = "Network"
				log.Resource = ""

				for k, v := range sockAddr {
					if log.Resource == "" {
						log.Resource = k + "=" + v
					} else {
						log.Resource = log.Resource + " " + k + "=" + v
					}
				}

				log.Data = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

			case SysListen: // fd
				var fd string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
				}

				log.Operation = "Network"
				log.Resource = ""
				log.Data = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

			default:
				continue
			}

			// get error message
			if msg.ContextSys.Retval < 0 {
				message := getErrorMessage(msg.ContextSys.Retval)
				if message != "" {
					log.Result = message
				} else {
					log.Result = fmt.Sprintf("Unknown (%d)", msg.ContextSys.Retval)
				}
			} else {
				log.Result = "Passed"
			}

			// push the generated log
			if mon.Logger != nil {
				go mon.Logger.PushLog(log)
			}
		}
	}
}
