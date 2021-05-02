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

// BuildHostLogBase Function
func (mon *SystemMonitor) BuildHostLogBase(msg ContextCombined) tp.Log {
	log := tp.Log{}

	log.UpdatedTime = kl.GetDateTimeNow()

	log.HostName = mon.HostName

	log.NamespaceName = ""
	log.PodName = ""
	log.ContainerID = ""
	log.ContainerName = ""

	log.HostPID = int32(msg.ContextSys.HostPID)
	log.PPID = int32(msg.ContextSys.PPID)
	log.PID = int32(msg.ContextSys.PID)
	log.UID = int32(msg.ContextSys.UID)

	if msg.ContextSys.EventID == SYS_EXECVE || msg.ContextSys.EventID == SYS_EXECVEAT {
		log.Source = mon.GetHostExecPath(msg.ContextSys.PPID)
	} else {
		log.Source = mon.GetHostExecPath(msg.ContextSys.PID)
	}

	if log.Source == "" {
		log.Source = string(msg.ContextSys.Comm[:bytes.IndexByte(msg.ContextSys.Comm[:], 0)])
	}

	return log
}

// UpdateHostLogs Function
func (mon *SystemMonitor) UpdateHostLogs() {
	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-mon.HostContextChan:
			if !valid {
				continue
			}

			// generate a log

			log := mon.BuildHostLogBase(msg)

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

				if mon.EnableAuditd && msg.ContextSys.Retval == PERMISSION_DENIED {
					continue
				}

			case SYS_OPENAT:
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
				log.Data = "fd=" + fd + " flags=" + fileOpenFlags

				if mon.EnableAuditd && msg.ContextSys.Retval == PERMISSION_DENIED {
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

			// get error message

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

			// push the generated log

			if mon.LogFeeder != nil {
				go mon.LogFeeder.PushLog(log)
			}
		}
	}
}
