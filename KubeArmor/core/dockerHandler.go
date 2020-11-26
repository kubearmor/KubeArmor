package core

import (
	"errors"
	"sort"
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

// DockerHandler Structure
type DockerHandler struct {
	DockerClient *client.Client
}

// NewDockerHandler Function
func NewDockerHandler() *DockerHandler {
	docker := &DockerHandler{}
	docker.DockerClient, _ = client.NewEnvClient()

	return docker
}

// Close Function
func (dh *DockerHandler) Close() {
	if dh.DockerClient != nil {
		dh.DockerClient.Close()
	}
}

// =============== //
// == Host Info == //
// =============== //

// GetHostName Function
func (dh *DockerHandler) GetHostName() (string, error) {
	if dh.DockerClient == nil {
		return "None", errors.New("No docker client")
	}

	info, err := dh.DockerClient.Info(context.Background())
	if err != nil {
		return "None", err
	}

	return info.Name, nil
}

// ==================== //
// == Container Info == //
// ==================== //

// GetContainerList Function
func (dh *DockerHandler) GetContainerList() ([]types.Container, error) {
	if dh.DockerClient == nil {
		return nil, errors.New("No docker client")
	}

	list, err := dh.DockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return nil, err
	}

	return list, nil
}

// GetEventChannel Function
func (dh *DockerHandler) GetEventChannel() <-chan events.Message {
	if dh.DockerClient != nil {
		event, _ := dh.DockerClient.Events(context.Background(), types.EventsOptions{})
		return event
	}

	return nil
}

// GetContainerInfo Function
func (dh *DockerHandler) GetContainerInfo(containerid string) (tp.Container, error) {
	if dh.DockerClient == nil {
		return tp.Container{}, errors.New("No docker client")
	}

	IndependentContainer := "__independent_container__"

	hostinfo, err := dh.DockerClient.Info(context.Background())
	if err != nil {
		return tp.Container{}, err
	}

	inspect, err := dh.DockerClient.ContainerInspect(context.Background(), containerid)
	if err != nil {
		return tp.Container{}, err
	}

	container := tp.Container{}

	// == container base == //

	container.ContainerID = inspect.ID
	container.ContainerName = strings.TrimLeft(inspect.Name, "/")

	container.Status = inspect.State.Status

	container.HostName = hostinfo.Name
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

	container.ImageID = inspect.Image
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
