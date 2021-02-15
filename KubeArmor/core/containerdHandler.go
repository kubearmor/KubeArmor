package core

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"

	pb "github.com/containerd/containerd/api/services/containers/v1"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/typeurl"
	"google.golang.org/grpc"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// ======================== //
// == Containerd Handler == //
// ======================== //

// Containerd Handler
var Containerd *ContainerdHandler

// init Function
func init() {
	// Spec -> google.protobuf.Any
	// https://github.com/opencontainers/runtime-spec/blob/master/specs-go/config.go

	const prefix = "types.containerd.io"
	major := strconv.Itoa(specs.VersionMajor)

	typeurl.Register(&specs.Spec{}, prefix, "opencontainers/runtime-spec", major, "Spec")
	typeurl.Register(&specs.Process{}, prefix, "opencontainers/runtime-spec", major, "Process")

	Containerd = NewContainerdHandler()
}

// ContainerdHandler Structure
type ContainerdHandler struct {
	// connection
	conn *grpc.ClientConn

	// client
	client pb.ContainersClient

	// context
	ctx context.Context

	// container stream
	containerStream pb.Containers_ListStreamClient

	// active containers
	containers []string
}

// NewContainerdHandler Function
func NewContainerdHandler() *ContainerdHandler {
	ch := &ContainerdHandler{}

	sockFile := "unix://"

	for _, candidate := range []string{"/var/run/containerd/containerd.sock", "/var/snap/microk8s/common/run/containerd.sock"} {
		if _, err := os.Stat(candidate); err == nil {
			sockFile = sockFile + candidate
			break
		}
	}

	if sockFile == "unix://" {
		return nil
	}

	conn, err := grpc.Dial(sockFile, grpc.WithInsecure())
	if err != nil {
		return nil
	}

	ch.conn = conn
	ch.client = pb.NewContainersClient(ch.conn)
	ch.ctx = namespaces.WithNamespace(context.Background(), "k8s.io")
	ch.containers = []string{}

	return ch
}

// Close Function
func (ch *ContainerdHandler) Close() {
	if ch.conn != nil {
		ch.conn.Close()
	}
}

// ==================== //
// == Container Info == //
// ==================== //

// GetContainerInfo Function
func (ch *ContainerdHandler) GetContainerInfo(containerID string) (tp.Container, error) {
	IndependentContainer := "__independent_container__"

	req := pb.GetContainerRequest{ID: containerID}
	res, err := ch.client.Get(ch.ctx, &req)
	if err != nil {
		return tp.Container{}, err
	}

	container := tp.Container{}

	// == container base == //

	container.ContainerID = res.Container.ID
	container.ContainerName = res.Container.ID[:12]

	container.HostName = kl.GetHostName()
	container.HostIP = kl.GetExternalIPAddr()

	containerLabels := res.Container.Labels
	if _, ok := containerLabels["io.kubernetes.pod.namespace"]; ok { // kubernetes
		if val, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
			container.NamespaceName = val
		} else {
			container.NamespaceName = IndependentContainer
		}
		if val, ok := containerLabels["io.kubernetes.pod.name"]; ok {
			container.ContainerGroupName = val
		} else {
			container.ContainerGroupName = container.ContainerName
		}
	} else { // containerd
		container.NamespaceName = IndependentContainer
		container.ContainerGroupName = container.ContainerName
	}

	container.ImageName = res.Container.Image

	container.Labels = []string{}
	for k, v := range res.Container.Labels {
		container.Labels = append(container.Labels, k+"="+v)
	}
	sort.Strings(container.Labels)

	iface, err := typeurl.UnmarshalAny(res.Container.Spec)
	if err != nil {
		return tp.Container{}, err
	}

	spec := iface.(*specs.Spec)
	container.AppArmorProfile = spec.Process.ApparmorProfile

	// == //

	return container, nil
}

// ======================= //
// == Containerd Events == //
// ======================= //

// GetContainerdContainers Function
func (ch *ContainerdHandler) GetContainerdContainers() []string {
	containers := []string{}

	req := pb.ListContainersRequest{}
	containerList, err := ch.client.List(ch.ctx, &req)
	if err != nil {
		return []string{}
	}

	for _, container := range containerList.Containers {
		containers = append(containers, container.ID)
	}

	return containers
}

// GetNewContainerdContainers Function
func (ch *ContainerdHandler) GetNewContainerdContainers(containers []string) []string {
	newContainers := []string{}

	for _, activeContainerID := range containers {
		exist := false

		for _, globalContainerID := range ch.containers {
			if activeContainerID == globalContainerID {
				exist = true
				break
			}
		}

		if !exist {
			newContainers = append(newContainers, activeContainerID)
		}
	}

	return newContainers
}

// GetDeletedContainerdContainers Function
func (ch *ContainerdHandler) GetDeletedContainerdContainers(containers []string) []string {
	deletedContainers := []string{}

	for _, globalContainerID := range ch.containers {
		exist := false

		for _, activeContainerID := range containers {
			if globalContainerID == activeContainerID {
				exist = true
				break
			}
		}

		if !exist {
			deletedContainers = append(deletedContainers, globalContainerID)
		}
	}

	ch.containers = containers

	return deletedContainers
}

// UpdateContainerdContainer Function
func (dm *KubeArmorDaemon) UpdateContainerdContainer(containerID, action string) {
	container := tp.Container{}

	if action == "start" {
		var err error

		// get container information from containerd client
		container, err = Containerd.GetContainerInfo(containerID)
		if err != nil {
			return
		}

		if container.ContainerID == "" {
			return
		}

		// skip paused containers in k8s
		if strings.HasPrefix(container.ImageName, "k8s.gcr.io/pause") {
			return
		}

		// skip if a container is a part of the following namespaces
		if kl.ContainsElement([]string{"kube-system"}, container.NamespaceName) {
			return
		}

		// add container to containers map
		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[containerID]; !ok {
			dm.Containers[containerID] = container
		} else {
			dm.ContainersLock.Unlock()
			return
		}
		dm.ContainersLock.Unlock()

		if ok := dm.UpdateContainerGroupWithContainer("ADDED", container); !ok {
			return
		}

		dm.LogFeeder.Printf("Detected a container (added/%s/%s)", container.NamespaceName, container.ContainerID[:12])

	} else if action == "destroy" {
		dm.ContainersLock.Lock()
		val, ok := dm.Containers[containerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return
		}

		container = val
		delete(dm.Containers, containerID)
		dm.ContainersLock.Unlock()

		if strings.HasPrefix(container.ImageName, "k8s.gcr.io/pause") {
			return
		}

		if ok := dm.UpdateContainerGroupWithContainer("DELETED", container); !ok {
			return
		}

		dm.LogFeeder.Printf("Detected a container (removed/%s/%s)", container.NamespaceName, container.ContainerID[:12])
	}
}

// MonitorContainerdEvents Function
func (dm *KubeArmorDaemon) MonitorContainerdEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	if Containerd == nil {
		return
	}

	dm.LogFeeder.Print("Started to monitor Containerd events")

	for {
		select {
		case <-StopChan:
			return

		default:
			containers := Containerd.GetContainerdContainers()

			newContainers := Containerd.GetNewContainerdContainers(containers)
			if len(newContainers) > 0 {
				for _, containerID := range newContainers {
					dm.UpdateContainerdContainer(containerID, "start")
				}
			}

			deletedContainers := Containerd.GetDeletedContainerdContainers(containers)
			if len(deletedContainers) > 0 {
				for _, containerID := range deletedContainers {
					dm.UpdateContainerdContainer(containerID, "destroy")
				}
			}
		}

		time.Sleep(time.Second * 1)
	}
}
