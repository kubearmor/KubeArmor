package core

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
	"golang.org/x/net/context"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ==================== //
// == Docker Handler == //
// ==================== //

// Docker Handler
var Docker *DockerHandler

// init Function
func init() {
	Docker = NewDockerHandler()
}

// DockerVersion Structure
type DockerVersion struct {
	APIVersion string `json:"ApiVersion"`
}

// DockerHandler Structure
type DockerHandler struct {
	DockerClient *client.Client
	Version      DockerVersion
}

// NewDockerHandler Function
func NewDockerHandler() *DockerHandler {
	docker := &DockerHandler{}

	// specify the docker api version that we want to use
	// Versioned API: https://docs.docker.com/engine/api/

	versionStr, err := kl.GetCommandOutputWithErr("curl", []string{"--unix-socket", "/var/run/docker.sock", "http://localhost/version"})
	if err != nil {
		return nil
	}

	json.Unmarshal([]byte(versionStr), &docker.Version)
	apiVersion, _ := strconv.ParseFloat(docker.Version.APIVersion, 64)

	if apiVersion >= 1.39 {
		// downgrade the api version to 1.39
		os.Setenv("DOCKER_API_VERSION", "1.39")
	} else {
		// set the current api version
		os.Setenv("DOCKER_API_VERSION", docker.Version.APIVersion)
	}

	// create a new client with the above env variable

	DockerClient, err := client.NewEnvClient()
	if err != nil {
		return nil
	}
	docker.DockerClient = DockerClient

	return docker
}

// Close Function
func (dh *DockerHandler) Close() {
	if dh.DockerClient != nil {
		dh.DockerClient.Close()
	}
}

// ==================== //
// == Container Info == //
// ==================== //

// GetContainerInfo Function
func (dh *DockerHandler) GetContainerInfo(containerID string) (tp.Container, error) {
	IndependentContainer := "__independent_container__"

	if dh.DockerClient == nil {
		return tp.Container{}, errors.New("No docker client")
	}

	inspect, err := dh.DockerClient.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return tp.Container{}, err
	}

	container := tp.Container{}

	// == container base == //

	container.ContainerID = inspect.ID
	container.ContainerName = strings.TrimLeft(inspect.Name, "/")

	container.HostName = kl.GetHostName()
	container.HostIP = kl.GetExternalIPAddr()

	containerLabels := inspect.Config.Labels
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
	} else if _, ok := containerLabels["com.docker.compose.project"]; ok { // docker-compose
		if val, ok := containerLabels["com.docker.compose.project"]; ok {
			container.NamespaceName = val
		} else {
			container.NamespaceName = IndependentContainer
		}
		if val, ok := containerLabels["com.docker.compose.service"]; ok {
			container.ContainerGroupName = val
		} else {
			container.ContainerGroupName = container.ContainerName
		}
	} else { // docker
		container.NamespaceName = IndependentContainer
		container.ContainerGroupName = container.ContainerName
	}

	container.ImageName = inspect.Config.Image

	container.Labels = []string{}
	for k, v := range inspect.Config.Labels {
		container.Labels = append(container.Labels, k+"="+v)
	}
	sort.Strings(container.Labels)

	container.AppArmorProfile = inspect.AppArmorProfile

	// == //

	return container, nil
}

// ========================== //
// == Docker Event Channel == //
// ========================== //

// GetEventChannel Function
func (dh *DockerHandler) GetEventChannel() <-chan events.Message {
	if dh.DockerClient != nil {
		event, _ := dh.DockerClient.Events(context.Background(), types.EventsOptions{})
		return event
	}

	return nil
}

// =================== //
// == Docker Events == //
// =================== //

// UpdateDockerContainer Function
func (dm *KubeArmorDaemon) UpdateDockerContainer(containerID, action string) {
	container := tp.Container{}

	if action == "start" {
		var err error

		// get container information from docker client
		container, err = Docker.GetContainerInfo(containerID)
		if err != nil {
			return
		}

		if container.ContainerID == "" {
			return
		}

		// skip paused containers in k8s
		if strings.HasPrefix(container.ContainerName, "k8s_POD") {
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

		dm.LogFeeder.Printf("Detected a container (added/%s/%s/%s)", container.NamespaceName, container.ContainerName, container.ContainerID[:12])

	} else if action == "stop" || action == "destroy" {
		// case 1: kill -> die -> stop
		// case 2: kill -> die -> destroy
		// case 3: destroy

		dm.ContainersLock.Lock()
		val, ok := dm.Containers[containerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return
		}

		container = val
		delete(dm.Containers, containerID)
		dm.ContainersLock.Unlock()

		if strings.HasPrefix(container.ContainerName, "k8s_POD") {
			return
		}

		if ok := dm.UpdateContainerGroupWithContainer("DELETED", container); !ok {
			return
		}

		dm.LogFeeder.Printf("Detected a container (removed/%s/%s/%s)", container.NamespaceName, container.ContainerName, container.ContainerID[:12])
	}
}

// MonitorDockerEvents Function
func (dm *KubeArmorDaemon) MonitorDockerEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	if Docker == nil {
		return
	}

	dm.LogFeeder.Print("Started to monitor Docker events")

	EventChan := Docker.GetEventChannel()

	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-EventChan:
			if !valid {
				continue
			}

			// if message type is container
			if msg.Type == "container" {
				dm.UpdateDockerContainer(msg.ID, msg.Action)
			}
		}
	}
}
