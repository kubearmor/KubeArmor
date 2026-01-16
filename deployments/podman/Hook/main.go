// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/types"
	"github.com/opencontainers/runtime-spec/specs-go"
)

const (
	LOGPATH                    = "/var/log/ka-hook.log"
	rootfulContainersPath      = "/var/lib/containers/storage/overlay-containers"
	containersFileName         = "containers.json"
	volatileContainersFileName = "volatile-containers.json"
)

var (
	kubeArmorSocket string
	runtimeSocket   string
	detached        bool
	logOutputPath   string
)

type ContainerMetadata struct {
	ID       string   `json:"id"`
	Names    []string `json:"names"`
	Image    string   `json:"image"`
	Metadata string   `json:"metadata"`
}

type MetadataDetails struct {
	ImageName string `json:"image-name"`
	Name      string `json:"name"`
}

func logError(err error) {
	if err == nil {
		return
	}
	// Append error to /tmp/podman-error.log
	f, ferr := os.OpenFile(logOutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if ferr != nil {
		// if even logging fails, fallback to stderr
		log.Println("error opening log file:", ferr)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "Error: %v\n", err)
}

func main() {
	flag.StringVar(&kubeArmorSocket, "kubearmor-socket", "/var/run/kubearmor/ka.sock", "KubeArmor socket")
	flag.StringVar(&runtimeSocket, "runtime-socket", "", "container runtime socket")
	flag.StringVar(&logOutputPath, "log-path", "/tmp/podman-error.log", "error log output path")
	flag.BoolVar(&detached, "detached", false, "run detached")
	flag.Parse()

	if runtimeSocket == "" {
		logError(fmt.Errorf("runtime socket must be set"))
	}
	if !strings.HasPrefix(runtimeSocket, "unix://") {
		runtimeSocket = "unix://" + runtimeSocket
	}
	if detached {
		if err := runDetached(); err != nil {
			logError(err)
		}
		os.Exit(0)
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		logError(err)
	}
	state := specs.State{}
	err = json.Unmarshal(input, &state)
	if err != nil {
		logError(err)
	}

	if err := run(state); err != nil {
		logError(err)
	}

}

func runDetached() error {
	// we need to make sure the process exits at some point
	time.AfterFunc(1*time.Minute, func() {
		logError(fmt.Errorf("failed to get containers, process timed out"))
	})
	conn := waitOnKubeArmor()
	defer conn.Close()

	handler, err := newPodmanHandler(runtimeSocket)
	if err != nil {
		return err
	}
	containers, err := handler.listContainers()
	if err != nil {
		return err
	}

	for _, container := range containers {
		data := types.HookRequest{
			Operation: types.HookContainerCreate,
			Detached:  true,
			Container: container,
		}

		dataJSON, err := json.Marshal(data)
		if err != nil {
			return err
		}

		_, err = conn.Write(dataJSON)
		if err != nil {
			return err
		}
		ack := make([]byte, 1024)
		_, err = conn.Read(ack)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func run(state specs.State) error {
	var container types.Container
	operation := types.HookContainerCreate
	// we try to connect to runtime here to make sure the socket is correct
	// before spawning a detached process
	_, err := newPodmanHandler(runtimeSocket)
	if err != nil {
		return err
	}

	container.ContainerID = state.ID
	if state.Status == specs.StateStopped {
		operation = types.HookContainerDelete
		return sendContainer(container, operation)
	}

	var appArmorProfile string
	var isKubeArmor bool
	specBytes, err := os.ReadFile(filepath.Join(state.Bundle, "config.json"))
	if err != nil {
		return err
	} else {
		var spec specs.Spec
		err = json.Unmarshal(specBytes, &spec)
		if err != nil {
			return err
		}
		appArmorProfile = spec.Process.ApparmorProfile // check if Process is nil??
		isKubeArmor = spec.Process.Args[0] == "/KubeArmor/kubearmor"
	}
	if isKubeArmor {
		err = startDetachedProcess()
		if err != nil {
			return err
		}
		// we still continue to try to send container details after starting the detached process
		// to make sure if it was a false positive (container trying to act as KubeArmor), we still
		// monitor it.
	}
	var homeDir string
	homeDir = os.Getenv("HOME")

	if homeDir == "" {
		passwdFile, err := os.Open("/etc/passwd")
		if err != nil {
			log.Printf("Failed to open /etc/passwd: %v", err)
		}
		defer passwdFile.Close()

		scanner := bufio.NewScanner(passwdFile)

		// Iterate through /etc/passwd to find the user with the desired directory
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) < 6 {
				continue // skip malformed lines
			}

			userHomeDir := fields[5]
			potentialPath := filepath.Join(userHomeDir, ".local/share/containers/storage/overlay-containers/containers.json")

			if _, err := os.Stat(potentialPath); err == nil {
				homeDir = userHomeDir
				break
			}
		}
	}

	if homeDir == "" {
		log.Printf("No matching user found with the overlay-containers path.")
	}

	rootlessContainersPath := filepath.Join(homeDir, ".local/share/containers/storage/overlay-containers")

	// Rootful Podman metadata paths
	metadataPath1 := filepath.Join(rootfulContainersPath, containersFileName)
	metadataPath2 := filepath.Join(rootfulContainersPath, volatileContainersFileName)

	// Rootless Podman metadata paths
	metadataPath3 := filepath.Join(rootlessContainersPath, containersFileName)
	metadataPath4 := filepath.Join(rootlessContainersPath, volatileContainersFileName)

	var paths []string

	isRootFullPodman := runtimeSocket == "unix:///run/podman/podman.sock" || runtimeSocket == "unix:///run/user/0/podman/podman.sock"

	if isRootFullPodman {
		paths = []string{metadataPath1, metadataPath2}
	} else {
		paths = []string{metadataPath3, metadataPath4}
	}

	var details MetadataDetails
	found := false
	for _, path := range paths {
		details, err = fetchContainerDetails(state.ID, path)
		if err == nil {
			found = true
			break
		} else {
			logError(fmt.Errorf("Error: %v\n", err))
		}
	}

	if !found {
		logError(fmt.Errorf("container with ID %s not found in any path", state.ID))
	}

	labels := []string{}

	for k, v := range state.Annotations {
		labels = append(labels, k+"="+v)
	}
	//add labels for policy matching
	labels = append(labels, "namespaceName="+"container_namespace")
	labels = append(labels, "containerType="+"podman")
	labels = append(labels, "kubearmor.io/container.name="+details.Name)

	nodename, nodeErr := os.Hostname()
	if nodeErr != nil {
		nodename = ""
	}

	container.Labels = strings.Join(labels, ",")

	status := "stopped"
	if state.Status == specs.StateRunning {
		status = "running"
	}
	container = types.Container{
		ContainerID:     state.ID,
		ContainerName:   details.Name,
		ContainerImage:  details.ImageName,
		AppArmorProfile: appArmorProfile,
		NamespaceName:   "container_namespace",
		EndPointName:    details.Name,
		NodeName:        nodename,
		Status:          status,
		Labels:          strings.Join(labels, ","),
	}
	container.PidNS, container.MntNS = getNS(state.Pid)

	return sendContainer(container, operation)
}

func fetchContainerDetails(containerID, metadataPath string) (MetadataDetails, error) {
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return MetadataDetails{}, fmt.Errorf("unable to read metadata file: %w", err)
	}

	var containers []ContainerMetadata
	err = json.Unmarshal(data, &containers)
	if err != nil {
		return MetadataDetails{}, fmt.Errorf("unable to parse metadata file: %w", err)
	}

	for _, container := range containers {
		if container.ID == containerID {
			var details MetadataDetails
			err := json.Unmarshal([]byte(container.Metadata), &details)
			if err != nil {
				return MetadataDetails{}, fmt.Errorf("unable to parse container metadata: %w", err)
			}
			return details, nil
		}
	}

	return MetadataDetails{}, fmt.Errorf("container with ID %s not found", containerID)
}

func getNS(pid int) (uint32, uint32) {
	var pidNS uint32
	var mntNS uint32

	nsPath := fmt.Sprintf("/proc/%d/ns", pid)

	pidLink, err := os.Readlink(filepath.Join(nsPath, "pid"))
	if err == nil {
		if _, err := fmt.Sscanf(pidLink, "pid:[%d]\n", &pidNS); err != nil {
			logError(err)
		}
	}

	mntLink, err := os.Readlink(filepath.Join(nsPath, "mnt"))
	if err == nil {
		if _, err := fmt.Sscanf(mntLink, "mnt:[%d]\n", &mntNS); err != nil {
			logError(err)
		}
	}
	return pidNS, mntNS
}

func sendContainer(container types.Container, operation types.HookOperation) error {
	conn, err := net.Dial("unix", kubeArmorSocket)
	if err != nil {
		// not returning error here because this can happen in multiple cases
		// that we don't want container creation to be blocked on:
		// - hook was created before KubeArmor was running so the socket doesn't exist yet
		// - KubeArmor crashed so there is nothing listening on socket
		return nil
	}

	defer conn.Close()

	data := types.HookRequest{
		Operation: operation,
		Detached:  false,
		Container: container,
	}

	dataJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	for {
		_, err = conn.Write(dataJSON)
		if err != nil {
			return err
		}
		ack := make([]byte, 1024)
		n, err := conn.Read(ack)
		if err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		response := ack[:n]
		if bytes.Equal(response, []byte("ok")) {
			return nil
		} else {
			time.Sleep(50 * time.Millisecond) // try again in 50 ms
			continue
		}

	}
}

func waitOnKubeArmor() net.Conn {
	for {
		conn, err := net.Dial("unix", kubeArmorSocket)
		if err == nil {
			return conn
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func startDetachedProcess() error {
	args := os.Args[1:]
	args = append(args, "--detached")
	cmd := exec.Command(os.Args[0], args...)
	logFile, err := os.OpenFile(logOutputPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	err = cmd.Start()
	if err != nil {
		return err
	}
	return cmd.Process.Release()
}
