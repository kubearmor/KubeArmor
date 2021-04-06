package audit

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hpcloud/tail"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ================== //
// == Audit Logger == //
// ================== //

type AuditLogger struct {
	// audit log monitoring flag
	WatchLogs bool

	// logs
	LogFeeder *fd.Feeder

	// host name
	HostName string

	// container id -> cotnainer
	Containers     *map[string]tp.Container
	ContainersLock **sync.Mutex

	// container id -> pid
	ActivePidMap     *map[string]tp.PidMap
	ActivePidMapLock **sync.Mutex

	// container id -> host pid
	ActiveHostPidMap     *map[string]tp.PidMap
	ActiveHostPidMapLock **sync.Mutex

	// GKE
	IsCOS bool
}

// NewAuditLogger Function
func NewAuditLogger(feeder *fd.Feeder, HomeDir string, containers *map[string]tp.Container, containersLock **sync.Mutex, activePidMap *map[string]tp.PidMap, activePidMapLock **sync.Mutex, activeHostPidMap *map[string]tp.PidMap, activeHostPidMapLock **sync.Mutex) *AuditLogger {
	adt := new(AuditLogger)

	adt.WatchLogs = true

	adt.LogFeeder = feeder

	adt.HostName = kl.GetHostName()

	adt.Containers = containers
	adt.ContainersLock = containersLock

	adt.ActivePidMap = activePidMap
	adt.ActivePidMapLock = activePidMapLock

	adt.ActiveHostPidMap = activeHostPidMap
	adt.ActiveHostPidMapLock = activeHostPidMapLock

	adt.IsCOS = false

	if kl.IsInK8sCluster() {
		if b, err := ioutil.ReadFile("/media/root/etc/os-release"); err == nil {
			s := string(b)
			if strings.Contains(s, "Container-Optimized OS") {
				// create directories
				if err := os.MkdirAll("/KubeArmor/audit", 0755); err != nil {
					adt.LogFeeder.Errf("Failed to create a target directory (/KubeArmor/audit, %s)", err.Error())
					return nil
				}

				for {
					// create symbolic link
					if err := exec.Command(HomeDir + "/GKE/create_symbolic_link.sh").Run(); err == nil {
						break
					} else {
						// wait until cos-auditd is ready
						time.Sleep(time.Second * 1)
					}
				}

				adt.IsCOS = true
			} else {
				// create directories
				if err := os.MkdirAll("/KubeArmor/audit", 0755); err != nil {
					adt.LogFeeder.Errf("Failed to create a target directory (/KubeArmor/audit, %s)", err.Error())
					return nil
				}

				// make a symbolic link
				if err := os.Symlink("/var/log/audit/audit.log", "/KubeArmor/audit/audit.log"); err != nil {
					adt.LogFeeder.Errf("Failed to make a symbolic link for audit.log (%s)", err.Error())
					return nil
				}
			}
		}
	}

	return adt
}

// DestroyAuditLogger Function
func (adt *AuditLogger) DestroyAuditLogger() error {
	// stop monitoring audit logs
	adt.WatchLogs = false

	return nil
}

// ============ //
// == Auditd == //
// ============ //

// GetProcessInfoFromHostPid Function
func (adt *AuditLogger) GetProcessInfoFromHostPid(log tp.Log, hostPid int32) tp.Log {
	ActiveHostPidMap := *(adt.ActiveHostPidMap)
	ActiveHostPidMapLock := *(adt.ActiveHostPidMapLock)

	ActiveHostPidMapLock.Lock()

	for id, pidMap := range ActiveHostPidMap {
		for pid, node := range pidMap {
			if hostPid == int32(pid) {
				log.ContainerID = id

				log.PPID = int32(node.PPID)
				log.PID = int32(node.PID)
				log.UID = int32(node.UID)

				break
			}
		}

		if log.ContainerID != "" {
			break
		}
	}

	ActiveHostPidMapLock.Unlock()

	if log.ContainerID == "" {
		ActiveHostPidMapLock.Lock()

		for id, pidMap := range ActiveHostPidMap {
			for pid, node := range pidMap {
				if hostPid == int32(pid) {
					log.ContainerID = id

					log.PPID = int32(node.PPID)
					log.PID = int32(node.PID)
					log.UID = int32(node.UID)

					break
				}
			}

			if log.ContainerID != "" {
				break
			}
		}

		ActiveHostPidMapLock.Unlock()
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

	if log.ContainerID != "" {
		ContainersLock.Lock()

		if val, ok := Containers[log.ContainerID]; ok {
			log.NamespaceName = val.NamespaceName
			log.PodName = val.ContainerGroupName
			log.ContainerName = val.ContainerName
		}

		ContainersLock.Unlock()
	}

	if log.ContainerID == "" {
		ContainersLock.Lock()

		for _, container := range Containers {
			if strings.HasPrefix(profileName, container.AppArmorProfile) {
				log.NamespaceName = container.NamespaceName
				log.PodName = container.ContainerGroupName
				log.ContainerID = container.ContainerID
				log.ContainerName = container.ContainerName
				break
			}
		}

		ContainersLock.Unlock()
	}

	return log
}

// GetExecPath Function
func (adt *AuditLogger) GetExecPath(containerID string, pid uint32) string {
	ActivePidMap := *(adt.ActivePidMap)
	ActivePidMapLock := *(adt.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	if pidMap, ok := ActivePidMap[containerID]; ok {
		if node, ok := pidMap[pid]; ok {
			if node.PID == pid {
				return node.ExecPath
			}
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
func (adt *AuditLogger) GetHostProcessInfoFromHostPid(log tp.Log, hostPid int32) tp.Log {
	ActiveHostPidMap := *(adt.ActiveHostPidMap)
	ActiveHostPidMapLock := *(adt.ActiveHostPidMapLock)

	ActiveHostPidMapLock.Lock()

	for _, pidMap := range ActiveHostPidMap {
		for pid, node := range pidMap {
			if hostPid == int32(pid) {
				log.PPID = int32(node.PPID)
				log.PID = int32(node.PID)
				log.UID = int32(node.UID)

				break
			}
		}
	}

	ActiveHostPidMapLock.Unlock()

	if log.PID == 0 {
		log.PPID = -1
		log.PID = hostPid
		log.UID = -1
	}

	return log
}

// GenerateAuditLog Function
func (adt *AuditLogger) GenerateAuditLog(hostPid int32, profileName, source, operation, resource, action, data string) {
	log := tp.Log{}

	log.UpdatedTime = kl.GetDateTimeNow()

	log.HostName = adt.HostName
	log.HostPID = hostPid
	log.Operation = operation

	if profileName == "kubearmor.host" {
		log = adt.GetHostProcessInfoFromHostPid(log, hostPid) // PPID, PID, UID
	} else {
		log = adt.GetProcessInfoFromHostPid(log, hostPid)           // ContainerID, PPID, PID, UID
		log = adt.GetContainerInfoFromContainerID(log, profileName) // NamespaceName, PodName, ContainerName
	}

	log = adt.UpdateSourceAndResource(log, source, resource) // Source, Resource

	log.Data = data

	if action == "AUDIT" {
		log.Result = "Passed"
	} else {
		log.Result = "Permission denied"
	}

	if adt.LogFeeder != nil {
		adt.LogFeeder.PushLog(log, -13)
	}
}

// MonitorAuditLogs Function
func (adt *AuditLogger) MonitorAuditLogs() {
	logFile := "/KubeArmor/audit/audit.log"

	if kl.IsK8sLocal() {
		logFile = "/var/log/audit/audit.log"
	}

	for adt.WatchLogs {
		// monitor audit logs
		logs, err := tail.TailFile(logFile, tail.Config{Follow: true})
		if err != nil {
			adt.LogFeeder.Err(err.Error())
			time.Sleep(time.Millisecond * 1)
			continue
		}

		for log := range logs.Lines {
			line := log.Text

			if !adt.WatchLogs {
				break
			}

			if !strings.Contains(line, "AVC") {
				continue
			} else if !strings.Contains(line, "DENIED") && !strings.Contains(line, "AUDIT") {
				continue
			} else if !strings.Contains(line, "exec") && !strings.Contains(line, "open") {
				continue
			}

			if adt.IsCOS {
				cosLine := ""

				for _, cosKV := range strings.Split(line, ",") {
					if strings.Contains(cosKV, "AVC apparmor=") {
						kv := strings.Split(cosKV, ":")
						if len(kv) == 2 {
							cosLine = kv[1]
							break
						}
					}
				}

				if cosLine == "" {
					continue
				}

				line = strings.Replace(cosLine, "\\\"", "\"", -1)
				line = line[1 : len(line)-1]
			}

			hostPid := int32(0)

			profileName := ""

			source := ""
			operation := ""
			resource := ""
			action := ""

			requested := ""
			denied := ""

			words := strings.Split(line, " ")

			for _, word := range words {
				if strings.HasPrefix(word, "pid=") {
					value := strings.Split(word, "=")
					pid, _ := strconv.Atoi(value[1])
					hostPid = int32(pid)
				} else if strings.HasPrefix(word, "profile=") {
					value := strings.Split(word, "=")
					profileName = strings.Replace(value[1], "\"", "", -1)
				} else if strings.HasPrefix(word, "comm=") {
					value := strings.Split(word, "=")
					source = strings.Replace(value[1], "\"", "", -1)
				} else if strings.HasPrefix(word, "operation=") {
					value := strings.Split(word, "=")
					operation = strings.Replace(value[1], "\"", "", -1)
				} else if strings.HasPrefix(word, "name=") {
					value := strings.Split(word, "=")
					resource = strings.Replace(value[1], "\"", "", -1)
				} else if strings.HasPrefix(word, "apparmor=") {
					value := strings.Split(word, "=")
					action = strings.Replace(value[1], "\"", "", -1)
				} else if strings.HasPrefix(word, "requested_mask=") {
					value := strings.Split(word, "=")
					requested = strings.Replace(value[1], "\"", "", -1)
				} else if strings.HasPrefix(word, "denied_mask=") {
					value := strings.Split(word, "=")
					denied = strings.Replace(value[1], "\"", "", -1)
				}
			}

			if operation == "exec" {
				operation = "Process"
			} else { // open
				operation = "File"
			}

			data := "requested=" + requested
			if denied != "" {
				data = data + " denied=" + denied
			}

			go adt.GenerateAuditLog(hostPid, profileName, source, operation, resource, action, data)
		}
	}
}
