// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

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
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/types"
	"github.com/opencontainers/runtime-spec/specs-go"
)

var (
	kubeArmorSocket string
	runtimeSocket   string
	detached        bool
)

func main() {
	flag.StringVar(&kubeArmorSocket, "kubearmor-socket", "/var/run/kubearmor/ka.sock", "KubeArmor socket")
	flag.StringVar(&runtimeSocket, "runtime-socket", "", "container runtime socket")
	flag.BoolVar(&detached, "detached", false, "run detached")
	flag.Parse()

	if runtimeSocket == "" {
		log.Println("runtime socket must be set")
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
	handler, err := getRuntimeHandler(runtimeSocket)
	if err != nil {
		return err
	}
	err = handler.close()
	if err != nil {
		log.Printf("failed to close runtime connection: %s", err.Error())
	}

	container.ContainerID = state.ID
	if state.Status == specs.StateStopped {
		operation = types.HookContainerDelete
		return sendContainer(container, operation)
	}

	var appArmorProfile string
	// the decision whether a container is KubeArmor container or not is done
	// based on two things:
	// - if we managed to get container spec, then we check the init process
	// - if we couldn't, we use container name from kubernetes annotations
	// this might lead to some containers acting as KubeArmor to spawn a detached
	// processes that are unneeded. However, the design of KubeArmor hook logic
	// is built around being idempotent so same requests being sent over and over
	// shouldn't be a security issue. We can always add more restrictions on that guess
	// but we always need to make sure to never introduce any false negatives as KubeArmor
	// running without knowledge of previous containers could be a security issue.
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
