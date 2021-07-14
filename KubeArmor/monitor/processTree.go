package monitor

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ============================ //
// == PID-to-ContainerID Map == //
// ============================ //

// LookupContainerID Function
func (mon *SystemMonitor) LookupContainerID(pidns, mntns, ppid, pid uint32) string {
	key := NsKey{PidNS: pidns, MntNS: mntns}

	mon.NsMapLock.RLock()
	if val, ok := mon.NsMap[key]; ok {
		mon.NsMapLock.RUnlock()
		return val
	}
	mon.NsMapLock.RUnlock()

	containerID := "None"

	// == //

	// look up container id from cgroup

	if cgroup, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
		cgroupScanner := bufio.NewScanner(cgroup)
		for cgroupScanner.Scan() {
			line := cgroupScanner.Text()

			// k8s1
			parts := kubePattern1.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}

			// k8s2
			parts = kubePattern2.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}

			// docker
			parts = dockerPattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}
		}

		cgroup.Close()

		// update newly found container id
		if containerID != "None" {
			mon.NsMapLock.Lock()
			mon.NsMap[key] = containerID
			mon.NsMapLock.Unlock()
			return containerID
		}
	}

	// look up container id from cmdline

	if cmdline, err := os.Open(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		cmdScanner := bufio.NewScanner(cmdline)
		for cmdScanner.Scan() {
			line := cmdScanner.Text()

			parts := strings.Split(line, "-id")
			if len(parts) < 2 {
				break
			}

			parts = strings.Split(parts[1], "-addr")
			if len(parts) < 2 {
				break
			}

			containerID = parts[0]
			if containerID != "" {
				break
			}
		}

		cmdline.Close()

		// update newly found container id
		if containerID != "None" {
			mon.NsMapLock.Lock()
			mon.NsMap[key] = containerID
			mon.NsMapLock.Unlock()
			return containerID
		}
	}

	// == //

	// look up container id from parent's cgroup

	if cgroup, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", ppid)); err == nil {
		cgroupScanner := bufio.NewScanner(cgroup)
		for cgroupScanner.Scan() {
			line := cgroupScanner.Text()

			// k8s1
			parts := kubePattern1.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}

			// k8s2
			parts = kubePattern2.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}

			// docker
			parts = dockerPattern.FindStringSubmatch(line)
			if parts != nil {
				containerID = parts[1]
				break
			}
		}

		cgroup.Close()

		// update newly found container id
		if containerID != "None" {
			mon.NsMapLock.Lock()
			mon.NsMap[key] = containerID
			mon.NsMapLock.Unlock()
			return containerID
		}
	}

	// look up container id from parent's cmdline

	if cmdline, err := os.Open(fmt.Sprintf("/proc/%d/cmdline", ppid)); err == nil {
		cmdScanner := bufio.NewScanner(cmdline)
		for cmdScanner.Scan() {
			line := cmdScanner.Text()

			parts := strings.Split(line, "-id")
			if len(parts) < 2 {
				break
			}

			parts = strings.Split(parts[1], "-addr")
			if len(parts) < 2 {
				break
			}

			containerID = parts[0]
			if containerID != "" {
				break
			}
		}

		cmdline.Close()

		// update newly found container id
		if containerID != "None" {
			mon.NsMapLock.Lock()
			mon.NsMap[key] = containerID
			mon.NsMapLock.Unlock()
			return containerID
		}
	}

	// == //

	return ""
}

func (mon *SystemMonitor) DeleteContainerIDFromNsMap(containerID string) {
	ns := NsKey{}

	mon.NsMapLock.RLock()
	defer mon.NsMapLock.RUnlock()

	for key, val := range mon.NsMap {
		if containerID == val {
			ns = key
			break
		}
	}

	if ns.PidNS != 0 && ns.MntNS != 0 {
		delete(mon.NsMap, ns)
	}
}

// ================== //
// == Process Tree == //
// ================== //

// BuildPidNode Function
func (mon *SystemMonitor) BuildPidNode(ctx SyscallContext, execPath string, args []string) tp.PidNode {
	node := tp.PidNode{}

	node.HostPPID = ctx.HostPPID
	node.HostPID = ctx.HostPID

	node.PPID = ctx.PPID
	node.PID = ctx.PID
	node.UID = ctx.UID

	node.Comm = string(ctx.Comm[:])
	node.ExecPath = execPath

	for idx, arg := range args {
		if idx == 0 {
			continue
		} else {
			node.ExecPath = node.ExecPath + " " + arg
		}
	}

	node.Exited = false

	return node
}

// AddActivePid Function
func (mon *SystemMonitor) AddActivePid(containerID string, node tp.PidNode) {
	ActivePidMap := *(mon.ActivePidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	// add pid node to ActivePidMap
	if pidMap, ok := ActivePidMap[containerID]; ok {
		pidMap[node.PID] = node
	} else {
		newPidMap := tp.PidMap{node.PID: node}
		ActivePidMap[containerID] = newPidMap
	}

	ActiveHostPidMap := *(mon.ActiveHostPidMap)

	// add pid node to ActiveHostPidMap
	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		pidMap[node.HostPID] = node
	} else {
		newPidMap := tp.PidMap{node.HostPID: node}
		ActiveHostPidMap[containerID] = newPidMap
	}
}

// GetExecPath Function
func (mon *SystemMonitor) GetExecPath(containerID string, pid uint32) string {
	ActivePidMap := *(mon.ActivePidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.RLock()
	defer ActivePidMapLock.RUnlock()

	if pidMap, ok := ActivePidMap[containerID]; ok {
		if node, ok := pidMap[pid]; ok {
			return node.ExecPath
		}
	}

	return ""
}

// GetExecPathWithHostPID Function
func (mon *SystemMonitor) GetExecPathWithHostPID(containerID string, hostPid uint32) string {
	ActiveHostPidMap := *(mon.ActiveHostPidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.RLock()
	defer ActivePidMapLock.RUnlock()

	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[hostPid]; ok {
			return node.ExecPath
		}
	}

	return ""
}

// DeleteActivePid Function
func (mon *SystemMonitor) DeleteActivePid(containerID string, ctx SyscallContext) {
	ActivePidMap := *(mon.ActivePidMap)
	ActivePidMapLock := *(mon.ActivePidMapLock)

	ActivePidMapLock.Lock()
	defer ActivePidMapLock.Unlock()

	// delete execve(at) pid
	if pidMap, ok := ActivePidMap[containerID]; ok {
		if node, ok := pidMap[ctx.PID]; ok {
			node.Exited = true
			node.ExitedTime = time.Now()
		}
	}

	ActiveHostPidMap := *(mon.ActiveHostPidMap)

	// delete execve(at) host pid
	if pidMap, ok := ActiveHostPidMap[containerID]; ok {
		if node, ok := pidMap[ctx.HostPID]; ok {
			node.Exited = true
			node.ExitedTime = time.Now()
		}
	}
}

// CleanUpExitedHostPids Function
func (mon *SystemMonitor) CleanUpExitedHostPids() {
	for range mon.Ticker.C {
		now := time.Now()

		ActivePidMap := *(mon.ActivePidMap)
		ActivePidMapLock := *(mon.ActivePidMapLock)

		ActivePidMapLock.Lock()

		for _, pidMap := range ActivePidMap {
			for pid, pidNode := range pidMap {
				if pidNode.Exited {
					if now.After(pidNode.ExitedTime.Add(time.Second * 5)) {
						delete(pidMap, pid)
					}
				}
			}
		}

		ActiveHostPidMap := *(mon.ActiveHostPidMap)

		for _, pidMap := range ActiveHostPidMap {
			for pid, pidNode := range pidMap {
				if pidNode.Exited {
					if now.After(pidNode.ExitedTime.Add(time.Second * 5)) {
						delete(pidMap, pid)
					}
				}
			}
		}

		ActivePidMapLock.Unlock()

		ActiveHostMap := *(mon.ActiveHostMap)
		ActiveHostMapLock := *(mon.ActiveHostMapLock)

		ActiveHostMapLock.Lock()

		for _, pidMap := range ActiveHostMap {
			for pid, pidNode := range pidMap {
				if pidNode.Exited {
					if now.After(pidNode.ExitedTime.Add(time.Second * 10)) {
						delete(pidMap, pid)
					}
				}
			}
		}

		ActiveHostMapLock.Unlock()
	}
}
