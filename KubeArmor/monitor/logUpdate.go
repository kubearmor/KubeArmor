// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package monitor

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
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
		// update pod info
		log.NamespaceName = val.NamespaceName
		log.Owner = &val.Owner
		log.PodName = val.EndPointName
		log.Labels = val.Labels

		// update container info
		log.ContainerName = val.ContainerName
		log.ContainerImage = val.ContainerImage

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
func (mon *SystemMonitor) BuildLogBase(eventID int32, msg ContextCombined, readlink bool) tp.Log {
	log := tp.Log{}

	timestamp, updatedTime := kl.GetDateTimeNow()

	log.Timestamp = timestamp
	log.UpdatedTime = updatedTime
	log.ContainerID = msg.ContainerID

	if log.ContainerID != "" {
		log = mon.UpdateContainerInfoByContainerID(log)
	} else {
		// update host policy flag
		log.PolicyEnabled = mon.Node.PolicyEnabled

		// update host visibility flags
		log.ProcessVisibilityEnabled = mon.Node.ProcessVisibilityEnabled
		log.FileVisibilityEnabled = mon.Node.FileVisibilityEnabled
		log.NetworkVisibilityEnabled = mon.Node.NetworkVisibilityEnabled
		log.CapabilitiesVisibilityEnabled = mon.Node.CapabilitiesVisibilityEnabled
	}

	if eventID != int32(DropAlert) {
		log.HostPPID = int32(msg.ContextSys.HostPPID)
		log.HostPID = int32(msg.ContextSys.HostPID)

		log.PPID = int32(msg.ContextSys.PPID)
		log.PID = int32(msg.ContextSys.PID)
		log.UID = int32(msg.ContextSys.UID)

		log.ProcessName = mon.GetExecPath(msg.ContainerID, msg.ContextSys, readlink)
		log.ParentProcessName = mon.GetParentExecPath(msg.ContainerID, msg.ContextSys, readlink, false)

		if msg.ContextSys.EventID == SysExecve || msg.ContextSys.EventID == SysExecveAt {
			log.Source = mon.GetParentExecPath(msg.ContainerID, msg.ContextSys, readlink, false)
		} else {
			log.Source = mon.GetCommand(msg.ContainerID, msg.ContextSys, readlink)
		}

		log.Cwd = strings.TrimRight(string(msg.ContextSys.Cwd[:]), "\x00") + "/"
		log.TTY = strings.TrimRight(string(msg.ContextSys.TTY[:]), "\x00")
		log.OID = int32(msg.ContextSys.OID)
	}

	return log
}

// UpdateLogBase Function (SYS_EXECVE, SYS_EXECVEAT)
func (mon *SystemMonitor) UpdateLogBase(ctx SyscallContext, log tp.Log) tp.Log {

	// update the process paths, since we would have received actual exec paths from bprm hook
	// in case bprm hook has not populated the map with full path, we will fallback to reading from procfs
	// else we will send out relative path

	processName := mon.GetExecPath(log.ContainerID, ctx, true)
	if processName != "" {
		log.ProcessName = processName
	}

	parentProcessName := mon.GetParentExecPath(log.ContainerID, ctx, true, false)
	if parentProcessName != "" {
		log.ParentProcessName = parentProcessName
		log.Source = parentProcessName
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
			log := mon.BuildLogBase(msg.ContextSys.EventID, msg, true)

			switch msg.ContextSys.EventID {
			case SysOpen:
				if len(msg.ContextArgs) != 2 {
					continue
				}

				var fileName string
				var fileOpenFlags string

				if val, ok := msg.ContextArgs[0].(string); ok {
					fileName = val
				}
				if val, ok := msg.ContextArgs[1].(string); ok {
					fileOpenFlags = val
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " flags=" + fileOpenFlags

			case SysOpenAt:
				if len(msg.ContextArgs) != 3 {
					continue
				}

				var fd string
				var fileName string
				var fileOpenFlags string

				if val, ok := msg.ContextArgs[0].(int32); ok {
					fd = strconv.Itoa(int(val))
				}
				if val, ok := msg.ContextArgs[1].(string); ok {
					fileName = val
				}
				if val, ok := msg.ContextArgs[2].(string); ok {
					fileOpenFlags = val
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd + " flags=" + fileOpenFlags

			case SysUnlink:
				if len(msg.ContextArgs) != 2 {
					continue
				}

				var fileName string
				if val, ok := msg.ContextArgs[1].(string); ok {
					fileName = val
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID))

			case SysUnlinkAt:
				if len(msg.ContextArgs) != 3 {
					continue
				}

				var fileName string
				var fileUnlinkAtFlags string

				if val, ok := msg.ContextArgs[1].(string); ok {
					fileName = val
				}
				if val, ok := msg.ContextArgs[2].(string); ok {
					fileUnlinkAtFlags = val
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " flags=" + fileUnlinkAtFlags

			case SysRmdir:
				if len(msg.ContextArgs) != 1 {
					continue
				}

				var fileName string
				if val, ok := msg.ContextArgs[0].(string); ok {
					fileName = val
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID))

			case SysChown:
				if len(msg.ContextArgs) != 3 {
					continue
				}
				var fileName string
				if val, ok := msg.ContextArgs[0].(string); ok {
					fileName = val
				}
				var uid int
				if val, ok := msg.ContextArgs[1].(int32); ok {
					uid = int(val)
				}

				var guid int
				if val, ok := msg.ContextArgs[2].(int32); ok {
					guid = int(val)
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " userid=" + strconv.Itoa(uid) + " group=" + strconv.Itoa(guid)

			case SysFChownAt:
				if len(msg.ContextArgs) != 5 {
					continue
				}
				var fileName string
				var uid int
				var guid int
				var mode int

				if val, ok := msg.ContextArgs[1].(string); ok {
					fileName = val
				}

				if val, ok := msg.ContextArgs[2].(int32); ok {
					uid = int(val)
				}

				if val, ok := msg.ContextArgs[3].(int32); ok {
					guid = int(val)
				}

				if val, ok := msg.ContextArgs[4].(int32); ok {
					mode = int(val)
				}

				log.Operation = "File"
				log.Resource = fileName
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " userid=" + strconv.Itoa(uid) + " group=" + strconv.Itoa(guid) + " mode=" + strconv.Itoa(mode)

			case SysSetuid, SysSetgid:
				if len(msg.ContextArgs) != 1 {
					continue
				}

				var uid int
				if val, ok := msg.ContextArgs[0].(int32); ok {
					uid = int(val)
				}
				log.Operation = "Syscall"
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " userid=" + strconv.Itoa(uid)

			case SysMount:
				if len(msg.ContextArgs) != 5 {
					continue
				}
				var source, target, fstype, data string
				var flags int

				if val, ok := msg.ContextArgs[0].(string); ok {
					source = val
				}
				if val, ok := msg.ContextArgs[1].(string); ok {
					target = val
				}
				if val, ok := msg.ContextArgs[2].(string); ok {
					fstype = val
				}
				if val, ok := msg.ContextArgs[3].(int32); ok {
					flags = int(val)
				}
				if val, ok := msg.ContextArgs[4].(string); ok {
					data = val
				}

				log.Operation = "Syscall"
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " source=" + source + " target=" + target + " filesystem=" + fstype + " mountflag=" + strconv.Itoa(flags) + " data=" + data

			case SysUmount:
				if len(msg.ContextArgs) != 2 {
					continue
				}
				var target string
				var flags int

				if val, ok := msg.ContextArgs[0].(string); ok {
					target = val
				}
				if val, ok := msg.ContextArgs[1].(int32); ok {
					flags = int(val)
				}

				log.Operation = "Syscall"
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " target=" + target + " flag=" + strconv.Itoa(flags)

			case SysClose:
				if len(msg.ContextArgs) != 1 {
					continue
				}

				var fd string

				if val, ok := msg.ContextArgs[0].(int32); ok {
					fd = strconv.Itoa(int(val))
				}

				log.Operation = "File"
				log.Resource = ""
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

			case SysPtrace:
				if len(msg.ContextArgs) != 3 {
					continue
				}

				var request string
				var pid string
				var binary string

				if val, ok := msg.ContextArgs[0].(string); ok {
					request = val
				}

				if val, ok := msg.ContextArgs[1].(int32); ok {
					pid = strconv.Itoa(int(val))
				}

				if val, ok := msg.ContextArgs[2].(string); ok {
					binary = val
				}

				log.Resource = binary
				log.Operation = "Process"
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " request=" + request + " pid=" + pid + " process=" + binary

			case SysSocket: // domain, type, proto
				if len(msg.ContextArgs) != 3 {
					continue
				}

				var sockDomain string
				var sockType string
				var sockProtocol int32

				if val, ok := msg.ContextArgs[0].(string); ok {
					sockDomain = val
				}
				if val, ok := msg.ContextArgs[1].(string); ok {
					sockType = val
				}
				if val, ok := msg.ContextArgs[2].(int32); ok {
					sockProtocol = val
				}

				log.Operation = "Network"
				log.Resource = "domain=" + sockDomain + " type=" + sockType + " protocol=" + GetProtocol(sockProtocol)
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID))

			case TCPConnect, TCPConnectv6, TCPAccept, TCPAcceptv6:
				if len(msg.ContextArgs) != 2 {
					continue
				}
				var sockAddr map[string]string
				var protocol string
				if val, ok := msg.ContextArgs[0].(string); ok {
					protocol = val
				}

				if val, ok := msg.ContextArgs[1].(map[string]string); ok {
					sockAddr = val
				}

				log.Operation = "Network"
				log.Resource = "remoteip=" + sockAddr["sin_addr"] + " port=" + sockAddr["sin_port"] + " protocol=" + protocol
				if msg.ContextSys.EventID == TCPConnect || msg.ContextSys.EventID == TCPConnectv6 {
					log.Data = "kprobe=tcp_connect"
				} else {
					log.Data = "kprobe=tcp_accept"
				}
				log.Data = log.Data + " domain=" + sockAddr["sa_family"]

			case SysConnect: // fd, sockaddr
				if len(msg.ContextArgs) != 2 {
					continue
				}

				var fd string
				var sockAddr map[string]string

				if val, ok := msg.ContextArgs[0].(int32); ok {
					fd = strconv.Itoa(int(val))
				}
				if val, ok := msg.ContextArgs[1].(map[string]string); ok {
					sockAddr = val
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

				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

			case SysAccept: // fd, sockaddr
				if len(msg.ContextArgs) != 2 {
					continue
				}

				var fd string
				var sockAddr map[string]string

				if val, ok := msg.ContextArgs[0].(int32); ok {
					fd = strconv.Itoa(int(val))
				}
				if val, ok := msg.ContextArgs[1].(map[string]string); ok {
					sockAddr = val
				}

				log.Operation = "Network"
				log.Resource = ""
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

				for k, v := range sockAddr {
					if log.Resource == "" {
						log.Resource = k + "=" + v
					} else {
						log.Resource = log.Resource + " " + k + "=" + v
					}
				}

			case SysBind: // fd, sockaddr
				if len(msg.ContextArgs) != 2 {
					continue
				}

				var fd string
				var sockAddr map[string]string

				if val, ok := msg.ContextArgs[0].(int32); ok {
					fd = strconv.Itoa(int(val))
				}
				if val, ok := msg.ContextArgs[1].(map[string]string); ok {
					sockAddr = val
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

				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

			case SysListen: // fd
				if len(msg.ContextArgs) != 2 {
					continue
				}

				var fd string

				if val, ok := msg.ContextArgs[0].(int32); ok {
					fd = strconv.Itoa(int(val))
				}

				log.Operation = "Network"
				log.Resource = ""
				log.Data = "syscall=" + GetSyscallName(int32(msg.ContextSys.EventID)) + " fd=" + fd

			case UDPSendMsg:
				if len(msg.ContextArgs) != 3 {
					continue
				}
				domains := ""
				if val, ok := msg.ContextArgs[1].(string); ok {
					domains = val
				}
				var sockAddr map[string]string
				if val, ok := msg.ContextArgs[0].(map[string]string); ok {
					sockAddr = val
				}
				qtype := ""
				if val, ok := msg.ContextArgs[2].(uint16); ok {
					if val == 1 {
						qtype = "A"
					}
					if val == 28 {
						qtype = "AAAA"
					}
				}

				log.Data = "kfunc=UDP_SENDMSG," + "domain=" + domains[:len(domains)-1] + // removed trailing . from domain name
					",daddr=" + sockAddr["sin_addr"] +
					",qtype=" + qtype
				log.Operation = "Network"
				log.Resource = "sa_family=" + sockAddr["sa_family"] + " sin_port=53"

			case DropAlert: // throttling alert
				log.Operation = "AlertThreshold"
				log.Type = "SystemEvent"
				log.MaxAlertsPerSec = cfg.GlobalCfg.MaxAlertPerSec
				log.DroppingAlertsInterval = cfg.GlobalCfg.ThrottleSec

			default:
				continue
			}

			if log.ProcessName == "" {
				switch log.Operation {
				case "Process":
					if log.Resource != "" {
						if res := strings.Split(log.Resource, " "); len(res) > 0 {
							log.ProcessName = res[0]
						}
					} else {
						mon.Logger.Debug("Dropping Process Event with empty processName and Resource")
						continue
					}
				case "Network", "File":
					if log.Source != "" {
						if src := strings.Split(log.Source, " "); len(src) > 0 {
							log.ProcessName = src[0]
						}
					} else {
						mon.Logger.Debugf("Dropping %s Event with empty processName and Source", log.Operation)
						continue
					}
				}
			}

			// fallback logic: in case we get relative path in log.Resource then we join cwd + resource to get pull path
			if !strings.HasPrefix(strings.Split(log.Resource, " ")[0], "/") && log.Cwd != "/" {
				log.Resource = filepath.Join(log.Cwd, log.Resource)
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

			// exec event
			log.ExecEvent.ExecID = strconv.FormatUint(msg.ContextSys.ExecID, 10)
			if comm := strings.TrimRight(string(msg.ContextSys.Comm[:]), "\x00"); len(comm) > 0 {
				log.ExecEvent.ExecutableName = comm
			}

			// push the generated log
			if mon.Logger != nil {
				go mon.Logger.PushLog(log)
				if isAuditedSyscall(msg.ContextSys.EventID) && log.Operation != "Syscall" {
					log.Action = "Audit"
					log.Operation = "Syscall"
					go mon.Logger.PushLog(log)
				}
			}
		}
	}
}
