package core

import (
	"context"
	"os"
	"strconv"
	"time"

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
	containerd context.Context
	docker     context.Context

	// container stream
	containerStream pb.Containers_ListStreamClient

	// active containers
	containers map[string]context.Context
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

	// docker namespace
	ch.docker = namespaces.WithNamespace(context.Background(), "moby")

	// containerd namespace
	ch.containerd = namespaces.WithNamespace(context.Background(), "k8s.io")

	ch.containers = map[string]context.Context{}

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
func (ch *ContainerdHandler) GetContainerInfo(ctx context.Context, containerID string) (tp.Container, error) {
	req := pb.GetContainerRequest{ID: containerID}
	res, err := ch.client.Get(ctx, &req)
	if err != nil {
		return tp.Container{}, err
	}

	container := tp.Container{}

	// == container base == //

	container.ContainerID = res.Container.ID
	container.ContainerName = res.Container.ID[:12]

	container.NamespaceName = "Unknown"
	container.ContainerGroupName = "Unknown"

	containerLabels := res.Container.Labels
	if _, ok := containerLabels["io.kubernetes.pod.namespace"]; ok { // kubernetes
		if val, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
			container.NamespaceName = val
		}
		if val, ok := containerLabels["io.kubernetes.pod.name"]; ok {
			container.ContainerGroupName = val
		}
	}

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
func (ch *ContainerdHandler) GetContainerdContainers() map[string]context.Context {
	containers := map[string]context.Context{}

	req := pb.ListContainersRequest{}

	if containerList, err := ch.client.List(ch.docker, &req); err == nil {
		for _, container := range containerList.Containers {
			containers[container.ID] = ch.docker
		}
	}

	if containerList, err := ch.client.List(ch.containerd, &req); err == nil {
		for _, container := range containerList.Containers {
			containers[container.ID] = ch.containerd
		}
	}

	return containers
}

// GetNewContainerdContainers Function
func (ch *ContainerdHandler) GetNewContainerdContainers(containers map[string]context.Context) map[string]context.Context {
	newContainers := map[string]context.Context{}

	for activeContainerID, context := range containers {
		if _, ok := ch.containers[activeContainerID]; !ok {
			newContainers[activeContainerID] = context
		}
	}

	return newContainers
}

// GetDeletedContainerdContainers Function
func (ch *ContainerdHandler) GetDeletedContainerdContainers(containers map[string]context.Context) map[string]context.Context {
	deletedContainers := map[string]context.Context{}

	for globalContainerID := range ch.containers {
		if _, ok := containers[globalContainerID]; !ok {
			delete(ch.containers, globalContainerID)
		}
	}

	ch.containers = containers

	return deletedContainers
}

// UpdateContainerdContainer Function
func (dm *KubeArmorDaemon) UpdateContainerdContainer(ctx context.Context, containerID, action string) {
	container := tp.Container{}

	if action == "start" {
		var err error

		// get container information from containerd client
		container, err = Containerd.GetContainerInfo(ctx, containerID)
		if err != nil {
			return
		}

		if container.ContainerID == "" {
			return
		}

		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[containerID]; !ok {
			dm.Containers[containerID] = container
		} else {
			dm.ContainersLock.Unlock()
			return
		}
		dm.ContainersLock.Unlock()

		dm.LogFeeder.Printf("Detected a container (added/%s)", container.ContainerID[:12])

	} else if action == "destroy" {
		dm.ContainersLock.Lock()
		if val, ok := dm.Containers[containerID]; !ok {
			dm.ContainersLock.Unlock()
			return
		} else {
			container = val
			delete(dm.Containers, containerID)
		}
		dm.ContainersLock.Unlock()

		dm.LogFeeder.Printf("Detected a container (removed/%s)", container.ContainerID[:12])
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

			if len(containers) == len(Containerd.containers) {
				time.Sleep(time.Millisecond * 10)
				continue
			}

			newContainers := Containerd.GetNewContainerdContainers(containers)
			if len(newContainers) > 0 {
				for containerID, context := range newContainers {
					dm.UpdateContainerdContainer(context, containerID, "start")
				}
			}

			deletedContainers := Containerd.GetDeletedContainerdContainers(containers)
			if len(deletedContainers) > 0 {
				for containerID, context := range deletedContainers {
					dm.UpdateContainerdContainer(context, containerID, "destroy")
				}
			}
		}

		time.Sleep(time.Millisecond * 10)
	}
}
