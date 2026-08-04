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

	// Auto-detect Kata Containers microVM environment by checking for the Kata shared root directory
	if _, err := os.Stat("/var/run/kata-containers/shared"); err == nil {
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		flagRetrieved, containerNS := kubearmorIdRetrieved(input)
		state := specs.State{}
		err = json.Unmarshal(input, &state)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		if err := runKata(state, flagRetrieved, containerNS); err != nil {
			log.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
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

func kubearmorIdRetrieved(input []byte) (bool, string) {
	var info map[string]interface{}

	if err := json.Unmarshal(input, &info); err != nil {
		log.Fatal(err)
	}

	dataMap, _ := info["annotations"].(map[string]interface{})
	containerName, _ := dataMap["io.kubernetes.cri.container-name"].(string)
	containerNS, _ := dataMap["io.kubernetes.cri.sandbox-namespace"].(string)
	if containerName == "kubearmor" {
		id, ok := info["id"].(string)
		if !ok {
			return false, containerNS
		}
		id = strings.Trim(id, `"`)
		_ = os.WriteFile("/tmp/id.json", []byte(id), 0600)
		return true, containerNS
	} else if _, err := os.Stat("/tmp/id.json"); err == nil {
		return true, containerNS
	}
	return false, containerNS
}

func runKata(state specs.State, flag bool, containerNS string) error {
	var container types.Container
	container = types.Container{
		ContainerID:   state.ID,
		NamespaceName: containerNS,
	}
	container.PidNS, container.MntNS = getNS(state.Pid)
	return sendContainerKata(container, flag)
}

func sendContainerKata(container types.Container, flag bool) error {
	dataJSON, err := json.Marshal(container)
	if err != nil {
		return err
	}

	srcFile, err := os.OpenFile("/tmp/output.json", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	if _, err := srcFile.Write(dataJSON); err != nil {
		return err
	}

	if _, err := srcFile.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if flag {
		val, err := os.ReadFile("/tmp/id.json")
		if err != nil {
			log.Printf("failed to read id.json: %v\n", err)
			return err
		}
		id := strings.TrimSpace(string(val))
		targetPath := filepath.Join("/var/run/kata-containers/shared/containers/"+id+"/rootfs", hookOutputFile)
		_ = os.MkdirAll(filepath.Dir(targetPath), 0755)

		dstFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			log.Printf("failed to open rootfs output file (%s) for container %s: %v\n", targetPath, id, err)
			return err
		}
		defer dstFile.Close()

		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return err
		}
	}

	return nil
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
