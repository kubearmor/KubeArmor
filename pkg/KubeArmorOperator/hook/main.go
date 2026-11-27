// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package main

import (
	"bytes"
	"context"
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
	"syscall"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/types"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var (
	kubeArmorSocket string
	runtimeSocket   string
	hookOutputFile  string
	detached        bool
)

func main() {
	flag.StringVar(&kubeArmorSocket, "kubearmor-socket", "/var/run/kubearmor/ka.sock", "KubeArmor socket")
	flag.StringVar(&runtimeSocket, "runtime-socket", "", "container runtime socket")
	flag.StringVar(&hookOutputFile, "hook-output", "/opt/kubearmor_hook_output.json", "output file path for Kata container events")
	flag.BoolVar(&detached, "detached", false, "run detached")
	flag.Parse()

	// Auto-detect Kata Containers microVM environment by checking
	// for the Kata shared root directory
	if runtimeSocket == "" && !detached {
		if _, err := os.Stat("/var/run/kata-containers/shared"); err == nil {
			input, err := io.ReadAll(os.Stdin)
			if err != nil {
				log.Printf("kata hook: failed to read stdin: %v", err)
				os.Exit(0)
			}

			var state specs.State
			if err := json.Unmarshal(input, &state); err != nil {
				log.Printf("kata hook: failed to unmarshal OCI state: %v", err)
				os.Exit(0)
			}

			if err := runKata(state); err != nil {
				log.Printf("kata hook: %v", err)
			}
			// Fail-open so hook issues never block container lifecycle
			os.Exit(0)
		}
	}
	if runtimeSocket == "" && detached {
		log.Println("runtime socket must be set for detached mode")
		os.Exit(1)
	}
	if detached {
		if err := runDetached(); err != nil {
			log.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	state := specs.State{}
	err = json.Unmarshal(input, &state)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	if err := run(state); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func runKata(state specs.State) error {
	// Skip CRI pod sandbox (pause) containers
	if state.Annotations["io.kubernetes.cri.container-type"] == "sandbox" {
		return nil
	}

	lockFile, err := os.OpenFile(kataHookLockFile, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file: %w", err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	containerName := firstNonEmpty(
		state.Annotations["io.kubernetes.cri.container-name"],
		state.Annotations["io.kubernetes.container.name"],
	)
	containerNS := firstNonEmpty(
		state.Annotations["io.kubernetes.cri.sandbox-namespace"],
		state.Annotations["io.kubernetes.pod.namespace"],
	)
	endPointName := firstNonEmpty(
		state.Annotations["io.kubernetes.cri.sandbox-name"],
		state.Annotations["io.kubernetes.pod.name"],
	)

	var spec specs.Spec
	specLoaded := false
	if state.Bundle != "" {
		if specBytes, err := os.ReadFile(filepath.Join(state.Bundle, "config.json")); err == nil {
			if err := json.Unmarshal(specBytes, &spec); err == nil {
				specLoaded = true
			}
		}
	}

	isKubeArmor := containerName == "kubearmor"
	if !isKubeArmor && specLoaded && spec.Process != nil && len(spec.Process.Args) > 0 {
		isKubeArmor = spec.Process.Args[0] == "/KubeArmor/kubearmor"
	}

	kaInfo, kaKnown := loadKataKubeArmorInfo()

	// Handle poststop (container stopped)
	if isKataPoststop(state) {
		if isKubeArmor || (kaKnown && kaInfo.ContainerID == state.ID) {
			_ = os.Remove(kataKubeArmorInfoFile)
			return nil
		}

		containers, err := loadKataContainers()
		if err != nil {
			return err
		}
		if _, exists := containers[state.ID]; !exists {
			return nil
		}
		delete(containers, state.ID)

		return persistAndSyncKataContainers(containers, kaInfo, kaKnown)
	}

	// Handle prestart (container starting)
	containers, err := loadKataContainers()
	if err != nil {
		return err
	}

	if isKubeArmor {
		kaInfo = kataKubeArmorInfo{
			ContainerID: state.ID,
			Rootfs:      resolveKataRootfs(state, spec, specLoaded),
		}
		if err := saveKataKubeArmorInfo(kaInfo); err != nil {
			return fmt.Errorf("failed to save kubearmor info: %w", err)
		}
		// Don't monitor KubeArmor itself; sync any already-buffered containers into its rootfs
		return syncKataContainersToRootfs(containers, kaInfo.Rootfs)
	}

	var appArmorProfile string
	if specLoaded && spec.Process != nil {
		appArmorProfile = spec.Process.ApparmorProfile
	} else if containerName != "" {
		appArmorProfile = strings.TrimPrefix(
			state.Annotations[fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", containerName)],
			"localhost/",
		)
	}

	if containerName == "" {
		containerName = state.ID
	}

	container := types.Container{
		ContainerID:     state.ID,
		ContainerName:   containerName,
		EndPointName:    endPointName,
		NamespaceName:   containerNS,
		AppArmorProfile: appArmorProfile,
	}
	if state.Pid > 0 {
		container.PidNS, container.MntNS = getNS(state.Pid)
	}

	containers[state.ID] = container
	return persistAndSyncKataContainers(containers, kaInfo, kaKnown)
}

func runDetached() error {
	// we need to make sure the process exits at some point
	time.AfterFunc(1*time.Minute, func() {
		log.Println("failed to get containers, process timed out")
		os.Exit(1)
	})
	conn := waitOnKubeArmor()
	defer conn.Close()

	handler, err := getRuntimeHandler(runtimeSocket)
	if err != nil {
		return err
	}
	containers, err := handler.listContainers(context.Background())
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
	if runtimeSocket != "" {
		handler, err := getRuntimeHandler(runtimeSocket)
		if err == nil {
			err = handler.close()
			if err != nil {
				log.Printf("failed to close runtime connection: %s", err.Error())
			}
		}
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
		// revert back to annotations
		containerName := state.Annotations["io.kubernetes.container.name"]
		appArmorProfile = strings.TrimPrefix(
			state.Annotations[fmt.Sprintf("container.apparmor.security.beta.kubernetes.io/%s", containerName)],
			"localhost/",
		)
		isKubeArmor = containerName == "kubearmor"
	} else {
		var spec specs.Spec
		err = json.Unmarshal(specBytes, &spec)
		if err != nil {
			return err
		}
		appArmorProfile = spec.Process.ApparmorProfile
		isKubeArmor = spec.Process.Args[0] == "/KubeArmor/kubearmor"
	}

	if isKubeArmor {
		err = startDetachedProcess()
		if err != nil {
			return err
		}
	}
	container = types.Container{
		ContainerID:     state.ID,
		AppArmorProfile: appArmorProfile,
	}
	container.PidNS, container.MntNS = getNS(state.Pid)

	return sendContainer(container, operation)
}

func getNS(pid int) (uint32, uint32) {
	var pidNS uint32
	var mntNS uint32

	nsPath := fmt.Sprintf("/proc/%d/ns", pid)

	pidLink, err := os.Readlink(filepath.Join(nsPath, "pid"))
	if err == nil {
		if _, err := fmt.Sscanf(pidLink, "pid:[%d]\n", &pidNS); err != nil {
			log.Println(err)
		}
	}

	mntLink, err := os.Readlink(filepath.Join(nsPath, "mnt"))
	if err == nil {
		if _, err := fmt.Sscanf(mntLink, "mnt:[%d]\n", &mntNS); err != nil {
			log.Println(err)
		}
	}
	return pidNS, mntNS
}

func sendContainer(container types.Container, operation types.HookOperation) error {
	conn, err := net.Dial("unix", kubeArmorSocket)
	if err != nil {
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
			time.Sleep(50 * time.Millisecond)
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
	logFile, err := os.OpenFile("/var/log/ka-hook.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
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

func getRuntimeHandler(socket string) (handler, error) {
	if strings.Contains(socket, "crio") {
		return newCRIOHandler(socket)
	} else if strings.Contains(socket, "containerd") {
		return newContainerdHandler(socket)
	}
	return nil, fmt.Errorf("only containerd and crio are supported")
}
