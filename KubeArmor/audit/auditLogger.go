package audit

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ================== //
// == Audit Logger == //
// ================== //

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

// AuditLogger Structure
type AuditLogger struct {
	// logging type
	logType string

	// logging path
	logFile string

	// hostname for logging
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
func NewAuditLogger(logOption, hostName string, containers map[string]tp.Container, containersLock *sync.Mutex, activePidMap map[string]tp.PidMap, activePidMapLock *sync.Mutex) *AuditLogger {
	al := &AuditLogger{}

	if kl.IsK8sLocal() {
		// create a test directory
		kl.GetCommandWithoutOutput("/bin/mkdir", []string{"-p", "/KubeArmor/audit"})

		// stop the Auditd daemon (just in case)
		kl.GetCommandWithoutOutput("/usr/sbin/service", []string{"auditd", "stop"})
	}

	if strings.Contains(logOption, "file:") {
		args := strings.Split(logOption, ":")

		al.logType = args[0]
		al.logFile = args[1]

		// create log file
		kl.GetCommandWithoutOutput("/bin/touch", []string{al.logFile})
	} else {
		kg.Printf("Use the default logging option (stdout) since %s is not a supported logging option")

		al.logType = "stdout"
		al.logFile = ""
	}

	al.HostName = hostName

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
	} else { // Otherwise
		// create audit log
		kl.GetCommandWithoutOutput("/bin/touch", []string{"/KubeArmor/audit/audit.log"})

		// load audit rules
		kl.GetCommandWithoutOutput("/sbin/auditctl", []string{"-R", "/etc/audit/audit.rules", ">", "/dev/null"})
	}

	return nil
}

// DestroyAuditLogger Function
func (al *AuditLogger) DestroyAuditLogger() {
	close(StopChan)

	if !al.isCOS {
		// stop the Auditd daemon
		kl.GetCommandWithoutOutput("/usr/bin/pkill", []string{"-9", "auditd"})
	}

	if kl.IsK8sLocal() {
		// remove the test directory
		kl.GetCommandWithoutOutput("/bin/rm", []string{"-rf", "/KubeArmor"})

		// start the Auditd daemon
		kl.GetCommandWithoutOutput("/usr/sbin/service", []string{"auditd", "start"})
	}
}

// ================ //
// == Audit Logs == //
// ================ //

// GetContainerInfoFromHostPid Function
func (al *AuditLogger) GetContainerInfoFromHostPid(hostPidIn string) (string, string) {
	hostPidInt, _ := strconv.Atoi(hostPidIn)
	hostPid := uint32(hostPidInt)

	al.ActivePidMapLock.Lock()
	defer al.ActivePidMapLock.Unlock()

	containerID := ""

	for id, v := range al.ActivePidMap {
		for pid := range v {
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
			return containerID, val.ContainerName
		}
		return containerID, ""
	}

	return "", al.HostName
}

// MonitorAuditLogs Function
func (al *AuditLogger) MonitorAuditLogs() {
	if !al.isCOS {
		// start auditd
		kl.GetCommandWithoutOutput("/sbin/auditd", []string{})
	}

	// monitor audit logs
	al.MonitorGenericAuditLogs()
}

func (al *AuditLogger) UpdateLogToFile(log string) {
	file, err := os.OpenFile(al.logFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		kg.Err(err.Error())
	}
	defer file.Close()

	_, err = file.WriteString(log)
	if err != nil {
		kg.Err(err.Error())
	}
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
			words := []string{}

			if al.isCOS {
				line = strings.Replace(line, "\\\"", "\"", -1)
			}

			// == //

			requiredKeywords := []string{
				"AVC",
				// "SYSCALL",
			}

			skip := true

			for _, keyword := range requiredKeywords {
				if strings.Contains(line, keyword) {
					skip = false
				}
			}

			if skip {
				continue
			}

			excludedKeywords := []string{
				"apparmor=\"STATUS\"",
				// "success=yes",
			}

			skip = false

			for _, keyword := range excludedKeywords {
				if strings.Contains(line, keyword) {
					skip = true
				}
			}

			if skip {
				continue
			}

			// == //

			if al.isCOS {
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

			filteringValues := []string{
				"requested_mask=",
				"denied_mask=",
				// "arch=",
				// "items=",
				// "auid=",
				// "euid=",
				// "ouid=",
				// "suid=",
				// "fsuid=",
				// "egid=",
				// "ogid=",
				// "sgid=",
				// "fsgid=",
				// "ses=",
				// "key=",
			}

			keyValToBeRemoved := []string{}
			hostPid := ""

			for _, keyVal := range words[2:] {
				for _, key := range filteringValues {
					if strings.Contains(keyVal, key) {
						keyValToBeRemoved = append(keyValToBeRemoved, keyVal)
						break
					}
				}

				if strings.HasPrefix(keyVal, "pid=") {
					value := strings.Split(keyVal, "=")
					hostPid = value[1]
				}
			}

			for _, keyVal := range keyValToBeRemoved {
				words = kl.RemoveStrFromSlice(words, keyVal)
			}

			// == //

			auditLog := tp.AuditLog{}
			auditLog.UpdatedTime = kl.GetDateTimeNow()

			auditLog.HostName = al.HostName
			auditLog.ContainerID, auditLog.ContainerName = al.GetContainerInfoFromHostPid(hostPid)

			auditLog.Message = strings.Join(words[:], " ")

			// == //

			if al.logType == "file" {
				log := fmt.Sprintf("UpdatedTime: %s, HostName: %s, ContainerID: %s, ContainerName: %s, Message: %s\n", auditLog.UpdatedTime, auditLog.HostName, auditLog.ContainerID, auditLog.ContainerName, auditLog.Message)
				al.UpdateLogToFile(log)
			} else { // stdout
				fmt.Println("UpdatedTime:", auditLog.UpdatedTime)
				fmt.Println("HostName:", auditLog.HostName)
				fmt.Println("ContainerID:", auditLog.ContainerID)
				fmt.Println("ContainerName:", auditLog.ContainerName)
				fmt.Println("Message:", auditLog.Message)
			}
		}
	}
}
