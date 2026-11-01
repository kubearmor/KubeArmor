// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	criV1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	criV1alpha2 "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

const (
	containerdK8sNs    = "k8s.io"
	containerdDockerNs = "moby"
)

func validatePath(path string) error {
	_, err := os.Stat(filepath.Clean(path))
	if err != nil && !os.IsPermission(err) {
		return err
	}

	return nil
}

func dockerSockHasContainer(containerID, sockPath string) bool {
	cli, err := client.New(client.WithHost("unix://" + sockPath))
	if err != nil {
		log.Warnf("Error in creating docker client: %v", err)
		return false
	}
	defer cli.Close()

	_, err = cli.ContainerInspect(context.Background(), containerID, client.ContainerInspectOptions{})
	if err != nil {
		return false
	}

	return true
}

func containerdSockHasContainer(containerID, sockPath string) bool {
	client, err := containerd.New(sockPath)
	if err != nil {
		log.Warnf("Error in creating containerd client: %v", err)
		return false
	}
	defer client.Close()

	k8sNsCtx := namespaces.WithNamespace(context.Background(), containerdK8sNs)
	dockerNsCtx := namespaces.WithNamespace(context.Background(), containerdDockerNs)

	// first check in k8s ns
	_, err = client.LoadContainer(k8sNsCtx, containerID)
	if err != nil {
		log.Warn("Container not found in K8s namespace")
	} else {
		return true
	}

	// check in docker ns also
	_, err = client.LoadContainer(dockerNsCtx, containerID)
	if err != nil {
		log.Warn("Container not found in Docker namespace")
		return false
	}

	return true
}

func dockershimSockHasContainer(containerID, sockPath string) bool {
	conn, err := grpc.NewClient("unix://"+sockPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Warnf("Error in creating dockershim client: %v", err)
		return false
	}

	defer conn.Close()

	dockershimClient := criV1alpha2.NewRuntimeServiceClient(conn)

	req := &criV1alpha2.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     false,
	}

	_, err = dockershimClient.ContainerStatus(context.Background(), req)
	if err != nil {
		return false
	}

	return true
}

func crioSockHasContainer(containerID, sockPath string) bool {
	conn, err := grpc.NewClient("unix://"+sockPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Warnf("Error in creating crio client: %v", err)
		return false
	}

	defer conn.Close()

	crioClient := criV1.NewRuntimeServiceClient(conn)

	req := &criV1.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	_, err = crioClient.ContainerStatus(context.Background(), req)
	if err != nil {
		return false
	}

	return true
}

func runtimeSockHasContainer(containerID, sockPath string) (bool, string) {
	// try all in case custom runtime wrapper is used
	if containerdSockHasContainer(containerID, sockPath) {
		return true, "containerd"
	}

	if crioSockHasContainer(containerID, sockPath) {
		return true, "cri-o"
	}

	if dockerSockHasContainer(containerID, sockPath) {
		return true, "docker"
	}

	if dockershimSockHasContainer(containerID, sockPath) {
		return true, "docker"
	}

	return false, ""
}

func getContainerRuntimePriority(first string) []string {
	priority := slices.Clone(common.ContainerRuntimeDefaultPriority)
	if i := slices.Index(priority, first); i > 0 {
		priority = slices.Delete(priority, i, i+1)
		priority = slices.Insert(priority, 1, first)
	}

	return priority
}

func DetectRuntimeViaMap(pathPrefix string, k8sRuntime string, explicitSocket string, log zap.SugaredLogger, cl *kubernetes.Clientset) (string, string) {
	// get container ID of snitch
	podName := os.Getenv("POD_NAME")
	namespace := os.Getenv("POD_NAMESPACE")
	pod, err := cl.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("Error in getting pod info: %v\n", err)
		return "NA", "NA"
	}

	var id string
	if len(pod.Status.ContainerStatuses) > 0 {
		id = pod.Status.ContainerStatuses[0].ContainerID // <type>://<container_id>, for example containerd://abcdef123456.....
	} else {
		log.Errorf("Error in getting pod info: %v\n", err)
		return "NA", "NA"
	}

	containerID := id
	if idx := strings.Index(id, "://"); idx != -1 {
		containerID = id[idx+3:]
	} else {
		log.Errorf("Unexpected ContainerID format: %s", id)
		return "NA", "NA"
	}

	if explicitSocket != "" {
		log.Infof("Using explicit socket file: %s", explicitSocket)

		hostPath := strings.TrimPrefix(explicitSocket, "unix://")
		if !filepath.IsAbs(hostPath) {
			log.Errorf("Explicit socket path must be absolute: %s", explicitSocket)
			return "NA", "NA"
		}

		hostPath = filepath.Clean(hostPath)
		checkPath := filepath.Clean(pathPrefix + hostPath)

		if _, err := os.Stat(checkPath); err == nil || os.IsPermission(err) {
			found, runtime := runtimeSockHasContainer(containerID, checkPath)
			if found {
				return runtime, hostPath
			}
		} else {
			log.Errorf("Explicit socket file not accessible: %s", err)
			return "NA", "NA"
		}
	}

	log.Infof("Checking for %s socket\n", k8sRuntime)

	for _, runtime := range getContainerRuntimePriority(k8sRuntime) {
		for _, path := range common.ContainerRuntimeSocketMap[runtime] {
			if err := validatePath(pathPrefix + path); err == nil {
				if found, _ := runtimeSockHasContainer(containerID, pathPrefix+path); found {
					return runtime, path
				}
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Couldn't detect runtime")
	return "NA", "NA"
}
