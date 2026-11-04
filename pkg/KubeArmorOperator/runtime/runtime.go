// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/common"
	"github.com/moby/moby/client"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
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

// criSockHasContainer probes a CRI v1 endpoint. Several runtimes (cri-o, cri-dockerd)
// answer CRI v1, so a successful ContainerStatus is not enough to call it cri-o:
// the endpoint's reported RuntimeName decides ("docker" for cri-dockerd).
func criSockHasContainer(containerID, sockPath string) (bool, string) {
	conn, err := grpc.NewClient("unix://"+sockPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Warnf("Error in creating CRI client: %v", err)
		return false, ""
	}

	defer conn.Close()

	criClient := criV1.NewRuntimeServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &criV1.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	if _, err = criClient.ContainerStatus(ctx, req); err != nil {
		return false, ""
	}

	return true, criRuntimeNameToRuntime(criClient, ctx)
}

func criRuntimeNameToRuntime(c criV1.RuntimeServiceClient, ctx context.Context) string {
	ver, err := c.Version(ctx, &criV1.VersionRequest{})
	if err == nil && strings.Contains(strings.ToLower(ver.GetRuntimeName()), "docker") {
		return "docker"
	}
	return "cri-o"
}

func isCriDockerdSocket(path string) bool {
	return strings.Contains(filepath.Base(strings.TrimPrefix(path, "unix://")), "cri-dockerd")
}

func runtimeSockHasContainer(containerID, sockPath string) (bool, string) {
	// try all in case custom runtime wrapper is used

	if containerdSockHasContainer(containerID, sockPath) {
		return true, "containerd"
	}

	if found, name := criSockHasContainer(containerID, sockPath); found {
		return true, name
	}

	if dockerSockHasContainer(containerID, sockPath) {
		return true, "docker"
	}

	if dockershimSockHasContainer(containerID, sockPath) {
		return true, "docker"
	}

	return false, ""
}

const (
	snitchContainerName = "snitch"
	idRetryAttempts     = 15
	idRetryInterval     = 2 * time.Second
)

// snitchContainerID picks the ID of the *currently running* snitch container from the
// pod status. Terminated containers (stale IDs left over after a restart) and
// containers that have no ID yet are ignored.
func snitchContainerID(pod *corev1.Pod, name string) (string, error) {
	statuses := pod.Status.ContainerStatuses
	if len(statuses) == 0 {
		return "", fmt.Errorf("pod %s/%s has no container statuses yet", pod.Namespace, pod.Name)
	}
	for _, cs := range statuses {
		if cs.Name != name {
			continue
		}
		if cs.State.Running == nil {
			return "", fmt.Errorf("container %q is not running yet", name)
		}
		idx := strings.Index(cs.ContainerID, "://")
		if idx == -1 || cs.ContainerID[idx+3:] == "" {
			return "", fmt.Errorf("container %q has unexpected or empty ContainerID %q", name, cs.ContainerID)
		}
		return cs.ContainerID[idx+3:], nil
	}
	return "", fmt.Errorf("container %q not found in pod status", name)
}

// waitForSnitchContainerID polls the pod until snitchContainerID succeeds, because the
// kubelet may not have published the container ID/state when snitch starts.
func waitForSnitchContainerID(ctx context.Context, getPod func(context.Context) (*corev1.Pod, error), name string, attempts int, interval time.Duration, log zap.SugaredLogger) (string, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		pod, err := getPod(ctx)
		if err == nil {
			var id string
			if id, err = snitchContainerID(pod, name); err == nil {
				return id, nil
			}
		}
		lastErr = err
		log.Warnf("Snitch container ID not ready (attempt %d/%d): %v", i+1, attempts, err)
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
	}
	return "", fmt.Errorf("gave up after %d attempts: %w", attempts, lastErr)
}

// ValidateDetection makes sure the detected runtime/socket pair can be turned into a
// DaemonSet by the operator (i.e. the socket is known for that runtime), so that snitch
// fails loudly instead of labelling the node with a combination that crashes KubeArmor.
func ValidateDetection(runtime, socket string) error {
	paths, ok := common.ContainerRuntimeSocketMap[runtime]
	if !ok || runtime == "nri" {
		return fmt.Errorf("unsupported runtime %q", runtime)
	}
	for _, p := range paths {
		if p == socket {
			return nil
		}
	}
	return fmt.Errorf("socket %q is not a supported socket for runtime %q (supported: %v)", socket, runtime, paths)
}

func DetectRuntimeViaMap(pathPrefix string, k8sRuntime string, explicitSocket string, log zap.SugaredLogger, cl *kubernetes.Clientset) (string, string, string) {

	// get container ID of snitch (waits until the container is reported Running)
	podName := os.Getenv("POD_NAME")
	namespace := os.Getenv("POD_NAMESPACE")

	containerID, err := waitForSnitchContainerID(context.TODO(), func(ctx context.Context) (*corev1.Pod, error) {
		return cl.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	}, snitchContainerName, idRetryAttempts, idRetryInterval, log)
	if err != nil {
		log.Errorf("Error in getting snitch container ID: %v\n", err)
		return "NA", "NA", "NA"
	}

	// cri-dockerd.sock is a CRI shim in front of Docker, not a socket KubeArmor can
	// monitor containers with. Treat it as a hint that the node runs Docker and
	// resolve the real monitorable socket (containerd/docker) from the socket map.
	if explicitSocket != "" && isCriDockerdSocket(explicitSocket) {
		log.Warnf("Explicit socket %s is a cri-dockerd (Docker CRI shim) socket, resolving the Docker/containerd socket instead", explicitSocket)
		explicitSocket = ""
		k8sRuntime = "docker"
	}

	if explicitSocket != "" {
		log.Infof("Using explicit socket file: %s", explicitSocket)

		hostPath := strings.TrimPrefix(explicitSocket, "unix://")
		if !filepath.IsAbs(hostPath) {
			log.Errorf("Explicit socket path must be absolute: %s", explicitSocket)
			return "NA", "NA", "NA"
		}

		hostPath = filepath.Clean(hostPath)
		checkPath := filepath.Clean(pathPrefix + hostPath)

		if _, err := os.Stat(checkPath); err == nil || os.IsPermission(err) {
			found, runtime := runtimeSockHasContainer(containerID, checkPath)
			if found {
				if (runtime == "docker" && strings.Contains(hostPath, "containerd")) || runtime == "containerd" {
					if nriPath, err := DetectNRI(pathPrefix); err == nil {
						return runtime, hostPath, nriPath
					} else {
						log.Warnf("NRI detection failed: %s", err)
					}
				}

				return runtime, hostPath, ""
			}
		} else {
			log.Errorf("Explicit socket file not accessible: %s", err)
			return "NA", "NA", "NA"
		}
	}

	log.Infof("Checking for %s socket\n", k8sRuntime)

	if k8sRuntime != "" {
		for _, path := range common.ContainerRuntimeSocketMap[k8sRuntime] {
			if _, err := os.Stat(pathPrefix + path); err == nil || os.IsPermission(err) {
				found, detectedRuntime := runtimeSockHasContainer(containerID, pathPrefix+path)
				if found {
					if (detectedRuntime == "docker" && strings.Contains(path, "containerd")) || detectedRuntime == "containerd" {
						if nriPath, err := DetectNRI(pathPrefix); err == nil {
							return detectedRuntime, path, nriPath
						} else {
							log.Warnf("%s", err)
						}
					}
					return detectedRuntime, path, ""
				}
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Couldn't detect k8s runtime location, searching for other runtime sockets")
	for _, paths := range common.ContainerRuntimeSocketMap {
		for _, path := range paths {
			if _, err := os.Stat(pathPrefix + path); err == nil || os.IsPermission(err) {
				found, k8sRuntime := runtimeSockHasContainer(containerID, pathPrefix+path)
				if found {
					return k8sRuntime, path, ""
				}
			} else {
				log.Warnf("%s", err)
			}
		}
	}
	log.Warn("Couldn't detect runtime")
	return "NA", "NA", "NA"
}
