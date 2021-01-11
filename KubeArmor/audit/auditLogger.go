package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ================== //
// == Audit Logger == //
// ================== //

// StopChan Channel
var StopChan chan struct{}

// AuditLogger Structure
type AuditLogger struct {
	// logging
	logType   string
	logTarget string
	logFeeder *fd.Feeder

	// host name
	HostName string

	// container id => cotnainer
	Containers     map[string]tp.Container
	ContainersLock *sync.Mutex

	// container id => pid
	ActivePidMap     map[string]tp.PidMap
	ActivePidMapLock *sync.Mutex

	// COS flag
	isCOS bool
}

// NewAuditLogger Function
func NewAuditLogger(logOption string, containers map[string]tp.Container, containersLock *sync.Mutex, activePidMap map[string]tp.PidMap, activePidMapLock *sync.Mutex) *AuditLogger {
	al := &AuditLogger{}

	StopChan = make(chan struct{})

	if strings.Contains(logOption, "grpc:") {
		args := strings.Split(logOption, ":")

		al.logType = args[0]
		al.logTarget = args[1] + ":" + args[2] // ip:port
		al.logFeeder = fd.NewFeeder(al.logTarget, "AuditLog")

	} else if strings.Contains(logOption, "file:") {
		args := strings.Split(logOption, ":")

		al.logType = args[0]
		al.logTarget = args[1] // file path
		al.logFeeder = nil

		// get the directory part from the path
		dirLog := filepath.Dir(al.logTarget)

		// create directories
		if err := os.MkdirAll(dirLog, 0755); err != nil {
			kg.Errf("Failed to create a target directory (%s)", err.Error())
			return nil
		}

		// create target file
		targetFile, err := os.Create(al.logTarget)
		if err != nil {
			kg.Errf("Failed to create a target file (%s)", err.Error())
			return nil
		}
		targetFile.Close()

	} else if logOption == "stdout" {
		al.logType = "stdout"
		al.logTarget = ""
		al.logFeeder = nil

	} else {
		al.logType = "none"
		al.logTarget = ""
		al.logFeeder = nil
	}

	al.HostName = kl.GetHostName()

	al.Containers = containers
	al.ContainersLock = containersLock

	al.ActivePidMap = activePidMap
	al.ActivePidMapLock = activePidMapLock

	al.isCOS = false

	return al
}

// InitAuditLogger Function
func (al *AuditLogger) InitAuditLogger(homeDir string) error {
	// check if COS
	if b, err := ioutil.ReadFile("/media/root/etc/os-release"); err == nil {
		s := string(b)
		if strings.Contains(s, "Container-Optimized OS") {
			al.isCOS = true

			kg.Printf("Trying to create a symbolic link to get audit logs")

			for {
				// create symbolic link
				if err := exec.Command(homeDir + "/GKE/create_symbolic_link.sh").Run(); err == nil {
					break
				} else {
					// wait until cos-auditd is ready
					time.Sleep(time.Second * 1)
				}
			}

			kg.Printf("Created a symbolic link to get audit logs")
		}
	}

	if kl.IsInK8sCluster() && !al.isCOS {
		// load audit rules
		if _, err := kl.GetCommandOutputWithErr("/sbin/auditctl", []string{"-R", "/etc/audit/audit.rules", ">", "/dev/null"}); err != nil {
			kg.Errf("Failed to load audit rules (%s)", err.Error())
			return err
		}
	}

	return nil
}

// DestroyAuditLogger Function
func (al *AuditLogger) DestroyAuditLogger() error {
	close(StopChan)

	if kl.IsInK8sCluster() && !al.isCOS {
		// stop the Auditd daemon
		if _, err := kl.GetCommandOutputWithErr("/usr/bin/pkill", []string{"-9", "auditd"}); err != nil {
			kg.Errf("Failed to stop auditd (%s)", err.Error())
			return err
		}
	}

	if al.logFeeder != nil {
		al.logFeeder.DestroyFeeder()
	}

	return nil
}

// ================ //
// == Audit Logs == //
// ================ //

// GetContainerInfoFromHostPid Function
func (al *AuditLogger) GetContainerInfoFromHostPid(hostPidInt int32) (string, string, string, string) {
	hostPid := uint32(hostPidInt)

	al.ActivePidMapLock.Lock()
	defer al.ActivePidMapLock.Unlock()

	containerID := ""

	for id, pidMap := range al.ActivePidMap {
		for pid := range pidMap {
			if hostPid == pid {
				containerID = id
				break
			}
		}

		if containerID != "" {
			break
		}
	}

	al.ContainersLock.Lock()
	defer al.ContainersLock.Unlock()

	if containerID != "" {
		if val, ok := al.Containers[containerID]; ok {
			return val.NamespaceName, val.ContainerGroupName, containerID, val.ContainerName
		}
		return "NOT_DISCOVERED_YET", "NOT_DISCOVERED_YET", containerID, "NOT_DISCOVERED_YET"
	}

	return "NOT_DISCOVERED_YET", "NOT_DISCOVERED_YET", "NOT_DISCOVERED_YET", "NOT_DISCOVERED_YET"
}

// MonitorAuditLogs Function
func (al *AuditLogger) MonitorAuditLogs() {
	if kl.IsInK8sCluster() && !al.isCOS {
		// start auditd
		kl.GetCommandOutputWithoutErr("/sbin/auditd", []string{})
	}

	// monitor audit logs
	al.MonitorGenericAuditLogs()
}

// MonitorGenericAuditLogs Function
func (al *AuditLogger) MonitorGenericAuditLogs() {
	logFile := "/KubeArmor/audit/audit.log"

	if kl.IsK8sLocal() {
		logFile = "/var/log/audit/audit.log"
	}

	// monitor audit logs
	cmd := exec.Command("/usr/bin/tail", "-f", logFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		kg.Err(err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		kg.Err(err.Error())
		return
	}

	r := bufio.NewReader(stdout)

	for {
		select {
		case <-StopChan:
			stdout.Close()
			return

		default:
			lineBytes, _, err := r.ReadLine()
			if err != nil {
				continue
			}
			line := string(lineBytes)

			// == //

			// if a log is not what we want, do not process the log (skip the following process)
			auditType := al.GetAuditType(line)
			if auditType == "" {
				continue
			}

			// == //

			// build an audit log based on a given log
			auditLog := al.GetAuditLog(auditType, line)

			// add container context into the audit log
			auditLog.HostName = al.HostName
			auditLog.NamespaceName, auditLog.PodName, auditLog.ContainerID, auditLog.ContainerName = al.GetContainerInfoFromHostPid(auditLog.HostPID)

			// == //

			if al.logType == "grpc" {
				al.logFeeder.SendAuditLog(auditLog)

			} else if al.logType == "file" {
				arr, _ := json.Marshal(auditLog)
				kl.StrToFile(string(arr), al.logTarget)

			} else if al.logType == "stdout" {
				arr, _ := json.Marshal(auditLog)
				fmt.Println(string(arr))
			}
		}
	}
}

// GetAuditType Function
func (al *AuditLogger) GetAuditType(line string) string {
	requiredKeywords := []string{
		"AVC",
		"SYSCALL",
	}

	auditType := ""

	for _, keyword := range requiredKeywords {
		if strings.Contains(line, keyword) {
			auditType = keyword
			break
		}
	}

	if auditType == "" {
		return ""
	}

	excludedKeywords := []string{
		"apparmor=\"STATUS\"",
		"success=yes",
	}

	pass := true

	for _, keyword := range excludedKeywords {
		if strings.Contains(line, keyword) {
			pass = false
		}
	}

	if !pass {
		return ""
	}

	return auditType
}

// GetAuditLog Function
func (al *AuditLogger) GetAuditLog(auditType, line string) tp.AuditLog {
	words := []string{}

	if al.isCOS {
		line = strings.Replace(line, "\\\"", "\"", -1)
		tempWords := strings.Split(line, ",")

		for _, tempWord := range tempWords {
			if strings.Contains(tempWord, "\"MESSAGE\":") {
				message := strings.Split(tempWord, ":")
				innerWords := strings.Split(message[1], " ")
				words = innerWords[1:]
			}
		}
	} else {
		tempWords := strings.Split(line, " ")
		words = tempWords[2:]
	}

	// == //

	auditLog := tp.AuditLog{}
	auditLog.UpdatedTime = kl.GetDateTimeNow()

	if auditType == "AVC" {
		for _, keyVal := range words {
			if strings.HasPrefix(keyVal, "pid=") {
				value := strings.Split(keyVal, "=")
				hostPID, _ := strconv.Atoi(value[1])
				auditLog.HostPID = int32(hostPID)

			} else if strings.HasPrefix(keyVal, "comm=") {
				value := strings.Split(keyVal, "=")
				auditLog.Source = strings.Replace(value[1], "\"", "", -1)

			} else if strings.HasPrefix(keyVal, "operation=") {
				value := strings.Split(keyVal, "=")
				auditLog.Operation = strings.Replace(value[1], "\"", "", -1)

			} else if strings.HasPrefix(keyVal, "name=") {
				value := strings.Split(keyVal, "=")
				auditLog.Resource = strings.Replace(value[1], "\"", "", -1)

			} else if strings.HasPrefix(keyVal, "apparmor=") {
				value := strings.Split(keyVal, "=")
				if value[1] == "\"ALLOWED\"" {
					auditLog.Result = "Allowed"
				} else if value[1] == "\"DENIED\"" {
					auditLog.Result = "Blocked"
				} else if value[1] == "\"AUDIT\"" {
					auditLog.Result = "Audited"
				} else {
					auditLog.Result = strings.Replace(value[1], "\"", "", -1)
				}
			}
		}
	} else if auditType == "SYSCALL" {
		for _, keyVal := range words {
			if strings.HasPrefix(keyVal, "pid=") {
				value := strings.Split(keyVal, "=")
				hostPID, _ := strconv.Atoi(value[1])
				auditLog.HostPID = int32(hostPID)

			} else if strings.HasPrefix(keyVal, "exe=") {
				value := strings.Split(keyVal, "=")
				auditLog.Source = strings.Replace(value[1], "\"", "", -1)

			} else if strings.HasPrefix(keyVal, "syscall=") {
				value := strings.Split(keyVal, "=")
				syscallNum, _ := strconv.Atoi(value[1])
				auditLog.Operation = "syscall"
				auditLog.Resource = getSyscallName(syscallNum)

			} else if strings.HasPrefix(keyVal, "exit=-") {
				value := strings.Split(keyVal, "=")
				errNo, _ := strconv.Atoi(value[1])
				auditLog.Result = fmt.Sprintf("Failed (%s)", getErrorMessage(errNo))
			}
		}
	}

	auditLog.RawData = strings.Join(words[:], " ")

	return auditLog
}
