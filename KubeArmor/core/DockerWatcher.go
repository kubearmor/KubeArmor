package core

import (
	"strings"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// =================== //
// == Docker Events == //
// =================== //

// UpdateContainerGroups Function
func (dm *KubeArmorDaemon) UpdateContainerGroups() {
	containerGroups := map[string]tp.ContainerGroup{}

	for _, container := range dm.Containers {
		namespaceName := container.NamespaceName
		containerGroupName := container.ContainerGroupName
		containerName := container.ContainerName

		// use namespace name and container group name as a key
		key := namespaceName + "|" + containerGroupName

		// if new container
		if oldGroup, ok := containerGroups[key]; !ok {
			newGroup := tp.ContainerGroup{}

			newGroup.NamespaceName = namespaceName
			newGroup.ContainerGroupName = containerGroupName

			newGroup.Labels = container.Labels
			newGroup.Identities = []string{}

			newGroup.Identities = append(newGroup.Identities, "namespaceName="+namespaceName)
			newGroup.Identities = append(newGroup.Identities, "containerGroupName="+containerGroupName)
			newGroup.Identities = append(newGroup.Identities, "containerName="+containerName)
			newGroup.Identities = append(newGroup.Identities, "hostName="+container.HostName)
			newGroup.Identities = append(newGroup.Identities, "imageName="+container.ImageName)

			for _, label := range container.Labels {
				if strings.Contains(label, "com.docker.compose") || strings.Contains(label, "io.kubernetes") {
					continue
				}

				if !kl.ContainsElement(newGroup.Identities, label) {
					newGroup.Identities = append(newGroup.Identities, label)
				}
			}

			if kl.IsK8sEnv() { // kubernetes
				dm.K8sPodsLock.Lock()

				k8sMetadata := K8s.GetK8sPod(dm.K8sPods, namespaceName, containerGroupName)
				for k, v := range k8sMetadata.Labels {
					if !kl.ContainsElement(newGroup.Labels, k+"="+v) {
						newGroup.Labels = append(newGroup.Labels, k+"="+v)
					}

					if kl.ContainsElement([]string{"controller-revision-hash", "pod-template-hash", "pod-template-generation"}, k) {
						continue
					}

					if !kl.ContainsElement(newGroup.Identities, k+"="+v) {
						newGroup.Identities = append(newGroup.Identities, k+"="+v)
					}
				}

				dm.K8sPodsLock.Unlock()
			}

			newGroup.Containers = []string{containerName}

			newGroup.SecurityPolicies = []tp.SecurityPolicy{}
			newGroup.AppArmorProfiles = map[string]string{containerName: container.AppArmorProfile}

			containerGroups[key] = newGroup
		} else { // if exist
			for _, label := range container.Labels {
				if !kl.ContainsElement(oldGroup.Labels, label) {
					oldGroup.Labels = append(oldGroup.Labels, label)
				}

				if strings.Contains(label, "com.docker.compose") || strings.Contains(label, "io.kubernetes") {
					continue
				}

				if !kl.ContainsElement(oldGroup.Identities, label) {
					oldGroup.Identities = append(oldGroup.Identities, label)
				}
			}

			oldGroup.Identities = append(oldGroup.Identities, "containerName="+container.ContainerName)

			if !kl.ContainsElement(oldGroup.Identities, "imageName="+container.ImageName) {
				oldGroup.Identities = append(oldGroup.Identities, "imageName="+container.ImageName)
			}

			if !kl.ContainsElement(oldGroup.Containers, container.ContainerName) {
				oldGroup.Containers = append(oldGroup.Containers, container.ContainerName)
				oldGroup.AppArmorProfiles[container.ContainerName] = container.AppArmorProfile
			}

			containerGroups[key] = oldGroup
		}
	}

	groupList := []tp.ContainerGroup{}
	for _, value := range containerGroups {
		groupList = append(groupList, value)
	}

	dm.ContainerGroupsLock.Lock()
	dm.ContainerGroups = groupList
	dm.ContainerGroupsLock.Unlock()
}

// UpdateContainer Function
func (dm *KubeArmorDaemon) UpdateContainer(containerID, action string) {
	defer kg.HandleErr()

	container := tp.Container{}

	if action == "start" {
		var err error

		// get container information from docker client
		container, err = Docker.GetContainerInfo(containerID)
		if err != nil {
			kg.Err(err.Error())
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

		kg.Printf("Detected a container (added/%s/%s)", container.NamespaceName, container.ContainerName)

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

		kg.Printf("Detected a container (removed/%s/%s)", container.NamespaceName, container.ContainerName)

	}

	dm.UpdateContainerGroups()
}

// UpdateContainerFromList Function
func (dm *KubeArmorDaemon) UpdateContainerFromList() {
	// update containers launched before the daemon is started
	containerlist, err := Docker.GetContainerList()
	if err != nil {
		kg.Err(err.Error())
		return
	}

	for _, container := range containerlist {
		name := strings.TrimLeft(container.Names[0], "/")

		// skip paused containers in k8s
		if strings.HasPrefix(name, "k8s_POD") {
			continue
		}

		if _, ok := dm.Containers[container.ID]; !ok {
			dm.UpdateContainer(container.ID, "start")
		}
	}
}

// MonitorDockerEvents Function
func (dm *KubeArmorDaemon) MonitorDockerEvents() {
	defer kg.HandleErr()
	defer WgDaemon.Done()

	kg.Print("Started to monitor Docker events")

	// dm.UpdateContainerFromList()

	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-dm.EventChan:
			if !valid {
				continue
			}

			// if message type is container
			if msg.Type == "container" {
				dm.UpdateContainer(msg.ID, msg.Action)
			}
		}
	}
}
