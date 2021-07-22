// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hpcloud/tail"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ================== //
// == Audit Logger == //
// ================== //

type AuditLogger struct {
	// host name
	HostName string

	// logs
	LogFeeder *fd.Feeder

	// container id -> cotnainer
	Containers     *map[string]tp.Container
	ContainersLock **sync.RWMutex

	// container id -> (host) pid
	ActivePidMap     *map[string]tp.PidMap
	ActiveHostPidMap *map[string]tp.PidMap
	ActivePidMapLock **sync.RWMutex

	// host pid -> host pid
	ActiveHostMap     *map[uint32]tp.PidMap
	ActiveHostMapLock **sync.RWMutex

	// GKE
	IsCOS bool
}

// NewAuditLogger Function
func NewAuditLogger(feeder *fd.Feeder,
	containers *map[string]tp.Container, containersLock **sync.RWMutex,
	activePidMap *map[string]tp.PidMap, activeHostPidMap *map[string]tp.PidMap, activePidMapLock **sync.RWMutex,
	activeHostMap *map[uint32]tp.PidMap, activeHostMapLock **sync.RWMutex) *AuditLogger {
	adt := new(AuditLogger)

	adt.HostName = kl.GetHostName()

	adt.LogFeeder = feeder

	adt.Containers = containers
	adt.ContainersLock = containersLock

	adt.ActivePidMap = activePidMap
	adt.ActiveHostPidMap = activeHostPidMap
	adt.ActivePidMapLock = activePidMapLock

	adt.ActiveHostMap = activeHostMap
	adt.ActiveHostMapLock = activeHostMapLock

	adt.IsCOS = false

	if kl.IsInK8sCluster() {
		if b, err := ioutil.ReadFile("/media/root/etc/os-release"); err == nil {
			s := string(b)

			// create directories
			if err := os.MkdirAll("/KubeArmor/audit", 0755); err != nil {
				adt.LogFeeder.Errf("Failed to create a target directory (/KubeArmor/audit, %s)", err.Error())
				return nil
			}

			if strings.Contains(s, "Container-Optimized OS") {
				adt.IsCOS = true

				// if audit.log is already there, remove it
				if _, err := os.Stat("/KubeArmor/audit/audit.log"); err == nil {
					if err := os.Remove("/KubeArmor/audit/audit.log"); err != nil {
						adt.LogFeeder.Errf("Failed to remove the existing audit log (/KubeArmor/audit/audit.log) (%s)", err.Error())
						return nil
					}
				}

				for range [300]int{} { // 5m * 60s = 300 secs
					ok := false

					// take each file from /var/log/audit
					if files, err := ioutil.ReadDir("/var/log/audit"); err == nil {
						for _, file := range files {
							if file.IsDir() {
								continue
							}

							fileName := file.Name()

							// cos-audit file looks like buffer.xxxx.log. if the file doesn't like this, skip it
							if !strings.HasPrefix(fileName, "buffer.") || !strings.HasSuffix(fileName, ".log") {
								continue
							}

							// make a symbolic link
							if err := os.Symlink("/var/log/audit/"+fileName, "/KubeArmor/audit/audit.log"); err != nil {
								adt.LogFeeder.Errf("Failed to make a symbolic link for audit.log (%s)", err.Error())
								return nil
							}

							ok = true
						}
					}

					if ok {
						break
					}

					// wait until cos-auditd is ready
					time.Sleep(time.Second * 1)
				}
			} else {
				// check if audit file is there
				if _, err := os.Stat("/var/log/audit/audit.log"); err != nil {
					adt.LogFeeder.Errf("Failed to find /var/log/audit/audit.log (%s)", err.Error())
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
	return nil
}

// ============ //
// == Auditd == //
// ============ //

// GenerateAuditLog Function
func (adt *AuditLogger) GenerateAuditLog(hostPid int32, profileName, source, operation, resource, action, data string) {
	log := tp.Log{}

	timestamp, updatedTime := kl.GetDateTimeNow()

	log.Timestamp = timestamp
	log.UpdatedTime = updatedTime

	log.HostPID = hostPid
	log.Operation = operation

	if profileName == "kubearmor.host" { // host
		log = adt.GetHostProcessInfoFromHostPid(log, uint32(hostPid)) // PPID, PID, UID
		log = adt.UpdateHostSourceAndResource(log, source, resource)  // Source, Resource
	} else { // containers
		log = adt.GetProcessInfoFromHostPid(log, uint32(hostPid))   // ContainerID, PPID, PID, UID
		log = adt.GetContainerInfoFromContainerID(log, profileName) // NamespaceName, PodName, ContainerName
		log = adt.UpdateSourceAndResource(log, source, resource)    // Source, Resource
	}

	log.Data = data

	if action == "AUDIT" {
		log.Result = "Passed"
	} else {
		log.Result = "Permission denied"
	}

	if adt.LogFeeder != nil {
		go adt.LogFeeder.PushLog(log)
	}
}

// MonitorAuditLogs Function
func (adt *AuditLogger) MonitorAuditLogs() {
	logFile := "/KubeArmor/audit/audit.log"

	if kl.IsK8sLocal() {
		logFile = "/var/log/audit/audit.log"
	}

	logs, err := tail.TailFile(logFile, tail.Config{Follow: true})
	if err != nil {
		adt.LogFeeder.Errf("Failed to read audit logs from %s (%s)", logFile, err.Error())
		return
	}

	for log := range logs.Lines {
		line := log.Text

		if !strings.Contains(line, "AVC") {
			continue
		} else if !strings.Contains(line, "DENIED") { // && !strings.Contains(line, "AUDIT") {
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
