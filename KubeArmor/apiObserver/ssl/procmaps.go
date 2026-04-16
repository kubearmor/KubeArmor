// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
//
// ssl/procmaps.go — /proc/<pid>/maps parser for container-aware SSL library discovery.
//
// Scans a process's memory map to find loaded SSL/TLS libraries, handling
// container mount namespaces via /proc/<pid>/root/<path> translation.
package ssl

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProcRoot is the path to the host's procfs. Defaults to /proc but should be
// set to /host/procfs (or whatever -procfsMount is) when running in a container
// without hostPID.
var ProcRoot = "/proc"

// SelfHostPID is KubeArmor's PID as seen from the host PID namespace.
// This is used to skip self-instrumentation when scanning host procfs.
// Set by InitSelfPID() at startup.
var SelfHostPID int

// SelfExePath is KubeArmor's executable path (from /proc/1/exe).
// Used to skip self-instrumentation by matching executable paths.
var SelfExePath string

// InitSelfPID discovers our identity for self-skip checks.
// It reads our executable path from /proc/1/exe and (if available)
// our host PID via the NSpid field in /proc/1/status.
func InitSelfPID() {
	// Get our executable path — this is the most reliable self-detection.
	if exe, err := os.Readlink("/proc/1/exe"); err == nil {
		SelfExePath = exe
	}

	// Also try NSpid for completeness (works when hostPID is true).
	data, err := os.ReadFile("/proc/1/status")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(line)
		// NSpid: <ns_pid> [<parent_ns_pid> ...] <host_pid>
		// Last field is the root (host) namespace PID.
		if len(fields) >= 3 { // need at least "NSpid:" + ns_pid + host_pid
			fmt.Sscanf(fields[len(fields)-1], "%d", &SelfHostPID)
		}
		break
	}
}

// IsSelfProcess checks if a host PID is our own process by comparing
// its executable path against SelfExePath.
func IsSelfProcess(pid int) bool {
	if SelfHostPID > 0 && pid == SelfHostPID {
		return true
	}
	if SelfExePath == "" {
		return false
	}
	exe, err := os.Readlink(fmt.Sprintf("%s/%d/exe", ProcRoot, pid))
	if err != nil {
		return false
	}
	return exe == SelfExePath
}

// infraBinaries lists executable basenames whose SSL traffic should not
// be captured. These are KubeArmor infrastructure processes whose gRPC
// calls (e.g. SPIRE attestation) create noise in the API event stream.
var infraBinaries = []string{
	"spire-agent",
	"spire-server",
	"spire_agent",
	"spire_server",
}

// IsInfraProcess returns true if the PID's executable matches a known
// infrastructure binary that should not be SSL-probed.
func IsInfraProcess(pid int) bool {
	exe, err := os.Readlink(fmt.Sprintf("%s/%d/exe", ProcRoot, pid))
	if err != nil {
		return false
	}
	basename := filepath.Base(exe)
	for _, name := range infraBinaries {
		if basename == name {
			return true
		}
	}
	return false
}

// MatchType controls how library names are matched in /proc/maps.
type MatchType int

const (
	// MatchEndsWith matches paths ending with the pattern (e.g. "libssl.so.3").
	MatchEndsWith MatchType = iota
	// MatchContains matches paths containing the pattern (e.g. "libpython").
	MatchContains
	// MatchExecutable matches the process binary name (via /proc/PID/exe)
	// and verifies it exports SSL symbols. Used for Node.js which statically
	// links OpenSSL.
	MatchExecutable
)

// ParseProcMaps reads /proc/<pid>/maps and returns all unique mapped
// library paths (ELF shared objects). Returns an error only on I/O failure.
func ParseProcMaps(pid int) ([]string, error) {
	f, err := os.Open(fmt.Sprintf("%s/%d/maps", ProcRoot, pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var result []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: addr perms offset dev inode path
		// e.g. "7f1234-7f5678 r-xp ... /usr/lib/x86_64-linux-gnu/libssl.so.3"
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[len(fields)-1]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		if _, dup := seen[path]; dup {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	return result, scanner.Err()
}

// FindLibInMaps searches for a library name in the parsed maps using the
// specified match strategy. Returns the first matching path or empty string.
func FindLibInMaps(maps []string, libName string, searchType MatchType) string {
	for _, path := range maps {
		basename := filepath.Base(path)
		switch searchType {
		case MatchEndsWith:
			if strings.HasSuffix(basename, libName) || basename == libName {
				return path
			}
		case MatchContains:
			if strings.Contains(basename, libName) {
				return path
			}
		}
	}
	return ""
}

// HostPath converts a container-local path to the host-accessible path
// via /proc/<pid>/root/. This handles mount namespace differences.
func HostPath(pid int, containerPath string) string {
	return fmt.Sprintf("%s/%d/root%s", ProcRoot, pid, containerPath)
}

// PidExists checks if a process is still alive by testing /proc/<pid>.
func PidExists(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("%s/%d", ProcRoot, pid))
	return err == nil
}

// GetProcStartTime reads the start time (field 22) from /proc/<pid>/stat.
// Used as part of the composite PID key for PID reuse protection.
func GetProcStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", ProcRoot, pid))
	if err != nil {
		return 0, err
	}
	// Field 22 (1-indexed) is starttime; find it after the (comm) field.
	s := string(data)
	closeIdx := strings.LastIndex(s, ")")
	if closeIdx < 0 || closeIdx+2 >= len(s) {
		return 0, fmt.Errorf("invalid /proc/%d/stat format", pid)
	}
	fields := strings.Fields(s[closeIdx+2:])
	// After "), fields are: state(0), ppid(1), ..., starttime(19)
	if len(fields) < 20 {
		return 0, fmt.Errorf("%s/%d/stat: too few fields after comm (%d)", ProcRoot, pid, len(fields))
	}
	var startTime uint64
	_, err = fmt.Sscanf(fields[19], "%d", &startTime)
	return startTime, err
}

// ListContainerPIDs returns all PIDs from /proc that have a cgroup
// indicating they are in a container (k8s, docker, containerd).
// This is a lightweight scan — no cgroupfs parsing needed.
func ListContainerPIDs() ([]int, error) {
	entries, err := os.ReadDir(ProcRoot)
	if err != nil {
		return nil, err
	}

	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}
		if pid <= 1 {
			continue
		}
		// Skip our own process to prevent self-instrumentation crashes.
		if IsSelfProcess(pid) {
			continue
		}
		// Skip known infrastructure processes (SPIRE, etc.) to avoid
		// capturing their SSL traffic (reduces overhead).
		if IsInfraProcess(pid) {
			continue
		}
		// Check if in a container: /proc/<pid>/cgroup contains
		// "kubepods", "docker", "containerd", or "cri-containerd"
		cgroupPath := fmt.Sprintf("%s/%d/cgroup", ProcRoot, pid)
		data, err := os.ReadFile(cgroupPath)
		if err != nil {
			continue
		}
		cgroup := string(data)
		if strings.Contains(cgroup, "kubepods") ||
			strings.Contains(cgroup, "docker") ||
			strings.Contains(cgroup, "containerd") {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}
