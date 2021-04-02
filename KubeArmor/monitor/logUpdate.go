package monitor

import (
	"bytes"
	"fmt"
	"strconv"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ========== //
// == Logs == //
// ========== //

// GetNameFromContainerID Function
func (mon *SystemMonitor) GetNameFromContainerID(id string) (string, string, string) {
	Containers := *(mon.Containers)
	ContainersLock := *(mon.ContainersLock)

	ContainersLock.Lock()
	defer ContainersLock.Unlock()

	if val, ok := Containers[id]; ok {
		return val.NamespaceName, val.ContainerGroupName, val.ContainerName
	}

	return "", "", ""
}

// BuildLogBase Function
func (mon *SystemMonitor) BuildLogBase(msg ContextCombined) tp.Log {
	log := tp.Log{}

	log.UpdatedTime = kl.GetDateTimeNow()

	log.HostName = mon.HostName

	if msg.ContainerID != "" {
		log.ContainerID = msg.ContainerID
		log.NamespaceName, log.PodName, log.ContainerName = mon.GetNameFromContainerID(log.ContainerID)
	}

	log.HostPID = int32(msg.ContextSys.HostPID)
	log.PPID = int32(msg.ContextSys.PPID)
	log.PID = int32(msg.ContextSys.PID)
	log.UID = int32(msg.ContextSys.UID)

	if msg.ContextSys.EventID == SYS_EXECVE || msg.ContextSys.EventID == SYS_EXECVEAT {
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
	execLogMap := map[int32]tp.Log{}

	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-mon.ContextChan:
			if !valid {
				continue
			}

			log := mon.BuildLogBase(msg)

			switch msg.ContextSys.EventID {
			case SYS_OPEN:
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
				log.Data = "flags=" + fileOpenFlags

				if msg.ContextSys.Retval == -13 {
					continue
				}

			case SYS_CLOSE:
				var fd string

				if len(msg.ContextArgs) == 1 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
				}

				log.Operation = "File"
				log.Resource = getSyscallName(int32(msg.ContextSys.EventID))
				log.Data = "fd=" + fd

			case SYS_EXECVE: // path, args
				var procExecPath string
				var procArgs []string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(string); ok {
						procExecPath = val
					}
					if val, ok := msg.ContextArgs[1].([]string); ok {
						procArgs = val
					}

					log.Operation = "Process"
					log.Resource = procExecPath

					for idx, arg := range procArgs {
						if idx == 0 {
							continue
						} else {
							log.Resource = log.Resource + " " + arg
						}
					}

					log.Data = ""

					execLogMap[log.HostPID] = log

					continue
				} else {
					log = execLogMap[log.HostPID]
					delete(execLogMap, log.HostPID)

					if msg.ContextSys.Retval == -13 {
						continue
					}
				}

			case SYS_EXECVEAT: // dirfd, path, args, flags
				var fd string
				var procExecPath string
				var procArgs []string
				var procExecFlag string

				if len(msg.ContextArgs) == 4 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
					if val, ok := msg.ContextArgs[1].(string); ok {
						procExecPath = val
					}
					if val, ok := msg.ContextArgs[2].([]string); ok {
						procArgs = val
					}
					if val, ok := msg.ContextArgs[3].(string); ok {
						procExecFlag = val
					}

					log.Operation = "Process"
					log.Resource = procExecPath

					for idx, arg := range procArgs {
						if idx == 0 {
							continue
						} else {
							log.Resource = log.Resource + " " + arg
						}
					}

					log.Data = "fd=" + fd + " flag=" + procExecFlag

					execLogMap[log.HostPID] = log

					continue
				} else {
					log = execLogMap[log.HostPID]

					delete(execLogMap, log.HostPID)

					if msg.ContextSys.Retval == -13 { // Permission Denied -> use auditLogger instead of this
						continue
					}
				}

			case SYS_SOCKET: // domain, type, proto
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
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID)) + " domain=" + sockDomain + " type=" + sockType + " protocol=" + sockProtocol
				log.Data = ""

			case SYS_CONNECT: // fd, sockaddr
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
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID))

				for k, v := range sockAddr {
					log.Resource = log.Resource + " " + k + "=" + v
				}

				log.Data = "fd=" + fd

			case SYS_ACCEPT: // fd, sockaddr
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
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID))
				log.Data = "fd=" + fd

				for k, v := range sockAddr {
					log.Resource = log.Resource + " " + k + "=" + v
				}

			case SYS_BIND: // fd, sockaddr
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
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID))

				for k, v := range sockAddr {
					log.Resource = log.Resource + " " + k + "=" + v
				}

				log.Data = "fd=" + fd

			case SYS_LISTEN: // fd
				var fd string

				if len(msg.ContextArgs) == 2 {
					if val, ok := msg.ContextArgs[0].(int32); ok {
						fd = strconv.Itoa(int(val))
					}
				}

				log.Operation = "Network"
				log.Resource = "syscall=" + getSyscallName(int32(msg.ContextSys.EventID))
				log.Data = "fd=" + fd

			default:
				continue
			}

			// == //

			if msg.ContextSys.Retval < 0 {
				message := getErrorMessage(msg.ContextSys.Retval)
				if message != "" {
					log.Result = fmt.Sprintf("%s", message)
				} else {
					log.Result = fmt.Sprintf("Unknown (%d)", msg.ContextSys.Retval)
				}
			} else {
				log.Result = "Passed"
			}

			// == //

			if mon.LogFeeder != nil {
				mon.LogFeeder.PushLog(log, msg.ContextSys.Retval)
			}

			// == //
		}
	}
}
