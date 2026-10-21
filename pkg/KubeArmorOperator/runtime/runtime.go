// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

func DetectNRI(pathPrefix string) (string, error) {
	for _, path := range common.ContainerRuntimeSocketMap["nri"] {
		if _, err := os.Stat(filepath.Clean(pathPrefix + path)); err == nil || os.IsPermission(err) {
			return path, nil
		} else {
			log.Warnf("%s", err)
		}
	}
	return "NA", fmt.Errorf("NRI not available")
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

func containerdSockHasContainer(containerID, sockPath string) (bool, string) {
	client, err := containerd.New(sockPath)
	if err != nil {
		log.Warnf("Error in creating containerd client: %v", err)
		return false, ""
	}
	defer client.Close()

	k8sNsCtx := namespaces.WithNamespace(context.Background(), containerdK8sNs)
	dockerNsCtx := namespaces.WithNamespace(context.Background(), containerdDockerNs)

	// first check in k8s ns
	_, err = client.LoadContainer(k8sNsCtx, containerID)
	if err != nil {
		log.Warn("Container not found in K8s namespace")
	} else {
		return true, containerdK8sNs
	}

	// check in docker ns also
	_, err = client.LoadContainer(dockerNsCtx, containerID)
	if err != nil {
		log.Warnf("Container not found in Docker namespace: %v", err)
		return false, ""
	}

	return true, containerdDockerNs
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

func runtimeSockHasContainer(containerID, sockPath string) (bool, string, string) {
	// try all in case custom runtime wrapper is used

	if found, namespace := containerdSockHasContainer(containerID, sockPath); found {
		return true, "containerd", namespace
	}

	if crioSockHasContainer(containerID, sockPath) {
		return true, "cri-o", ""
	}

	if dockerSockHasContainer(containerID, sockPath) {
		return true, "docker", ""
	}

	if dockershimSockHasContainer(containerID, sockPath) {
		return true, "docker", ""
	}

	return false, "", ""
}

var containerIDRegex = regexp.MustCompile(`[0-9a-f]{64}`)

// selfContainerID returns the ID of the container this process runs in, as
// seen in its cgroup path or mounts, or "" if it can't be determined.
// This will return the pause container ID.
// TODO: check for alternative ways to achieve this, the current implementation is not ideal.
func selfContainerID() string {
	for _, f := range []string{"/proc/self/cgroup", "/proc/self/mountinfo"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if m := containerIDRegex.FindAllString(string(data), -1); len(m) > 0 {
			return m[len(m)-1]
		}
	}
	return ""
}

func DetectRuntimeViaMap(pathPrefix string, k8sRuntime string, explicitSocket string, log zap.SugaredLogger, cl *kubernetes.Clientset) (detectedRuntime, socket, nriSocket, containerdNamespace string) {

	// get container ID of snitch
	podName := os.Getenv("POD_NAME")
	namespace := os.Getenv("POD_NAMESPACE")
	pod, err := cl.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("Error in getting pod info: %v\n", err)
		return "NA", "NA", "NA", "NA"
	}

	var id string
	if len(pod.Status.ContainerStatuses) > 0 {
		id = pod.Status.ContainerStatuses[0].ContainerID // <type>://<container_id>, for example containerd://abcdef123456.....
	} else {
		log.Errorf("Error in getting pod info: %v\n", err)
		return "NA", "NA", "NA", "NA"
	}

	containerID := id
	if idx := strings.Index(id, "://"); idx != -1 {
		containerID = id[idx+3:]
	} else {
		log.Errorf("Unexpected ContainerID format: %s", id)
		return "NA", "NA", "NA", "NA"
	}

	// The API ID can be stale after a container restart and wrapper runtimes
	// (e.g. robin://) report IDs the real runtime doesn't know, so prefer the
	// ID the kernel reports for this process.
	if selfID := selfContainerID(); selfID != "" && selfID != containerID {
		log.Warnf("Container ID from pod status (%s) differs from ID found in /proc (%s), using the latter", containerID, selfID)
		containerID = selfID
	}

	log.Infof("PodName=%s Namespace=%s id=%s containerid=%s", podName, namespace, id, containerID)

	found := false

	if explicitSocket != "" {
		log.Infof("Using explicit socket file: %s", explicitSocket)

		hostPath := strings.TrimPrefix(explicitSocket, "unix://")
		if !filepath.IsAbs(hostPath) {
			log.Errorf("Explicit socket path must be absolute: %s", explicitSocket)
			return "NA", "NA", "NA", "NA"
		}

		hostPath = filepath.Clean(hostPath)
		checkPath := filepath.Clean(pathPrefix + hostPath)

		if _, err := os.Stat(checkPath); err == nil || os.IsPermission(err) {
			found, detectedRuntime, containerdNamespace = runtimeSockHasContainer(containerID, checkPath)
			if found {
				if (detectedRuntime == "docker" && strings.Contains(hostPath, "containerd")) || detectedRuntime == "containerd" {
					if nriPath, err := DetectNRI(pathPrefix); err == nil {
						// NRI has no containerd namespace
						return detectedRuntime, hostPath, nriPath, ""
					} else {
						log.Warnf("NRI detection failed: %s", err)
					}
				}

				return detectedRuntime, hostPath, "", containerdNamespace
			}
		} else {
			log.Errorf("Explicit socket file not accessible: %s", err)
			return "NA", "NA", "NA", "NA"
		}
	}

	log.Infof("Checking for %s socket\n", k8sRuntime)

	if k8sRuntime != "" {
		for _, path := range common.ContainerRuntimeSocketMap[k8sRuntime] {
			if _, err := os.Stat(filepath.Clean(pathPrefix + path)); err == nil || os.IsPermission(err) {
				found, detectedRuntime, containerdNamespace = runtimeSockHasContainer(containerID, filepath.Clean(pathPrefix+path))
				if found {
					if (detectedRuntime == "docker" && strings.Contains(path, "containerd")) || detectedRuntime == "containerd" {
						if nriPath, err := DetectNRI(pathPrefix); err == nil {
							return detectedRuntime, path, nriPath, ""
						} else {
							log.Warnf("%s", err)
						}
					}
					return detectedRuntime, path, "", containerdNamespace
				}
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Couldn't detect k8s runtime location, searching for other runtime sockets")
	var runtimePriority = []string{"containerd", "docker", "nri", "cri-o"}

	for _, name := range runtimePriority {
		for _, path := range common.ContainerRuntimeSocketMap[name] {
			log.Infof("Checking %s runtime with socket %s", name, path)
			if _, err := os.Stat(filepath.Clean(pathPrefix + path)); err == nil || os.IsPermission(err) {
				found, detectedRuntime, containerdNamespace = runtimeSockHasContainer(containerID, filepath.Clean(pathPrefix+path))
				if found {
					log.Infof("Found socket %s for runtime %s at namespace %s", path, detectedRuntime, containerdNamespace)
					return detectedRuntime, path, "", containerdNamespace
				}
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Couldn't detect runtime")
	return "NA", "NA", "NA", "NA"
}
