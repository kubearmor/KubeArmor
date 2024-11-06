// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/state"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func (dm *KubeArmorDaemon) HandleFile(file string) {
	f, err := os.Open(file)
	if err != nil {
		dm.Logger.Errf("Failed to open file '%s': %v. Ensure the file exists and has appropriate permissions.", file, err.Error())
	}

	decoder := json.NewDecoder(f)
	for {
		var containerData tp.Container

		err = decoder.Decode(&containerData)
		if err != nil {
			if err == io.EOF {
				dm.Logger.Warnf("Reached the end of file '%s'.", file)
				break
			}
			dm.Logger.Errf("Error decoding JSON from file '%s': %v. Verify the file's format and content.", file, err)
			break
		}
		dm.handleContainerCreate(containerData)
	}

	defer f.Close()

	w, err := fsnotify.NewWatcher()
	if err != nil {
		dm.Logger.Errf("Error creating new watcher: (%s)", err.Error())
	}
	defer w.Close()

	err = w.Add(file)
	if err != nil {
		dm.Logger.Errf("Error adding file to watcher: (%s)", err.Error())
	}

	for {
		select {
		case err, ok := <-w.Errors:
			if !ok {
				dm.Logger.Warnf("Watcher error channel closed unexpectedly. Exiting watcher loop.")
				return
			}
			dm.Logger.Errf("Watcher error: (%s)", err.Error())

		case e, ok := <-w.Events:
			if !ok {
				dm.Logger.Warnf("File watcher event channel closed unexpectedly. Exiting watcher loop.")
				return
			}

			if e.Op&fsnotify.Write == fsnotify.Write {
				f, err := os.Open(file)
				if err != nil {
					dm.Logger.Errf("Error opening file: (%s)", err.Error())
					continue
				}
				defer f.Close()

				decoder := json.NewDecoder(f)
				for {
					var containerData tp.Container

					err = decoder.Decode(&containerData)
					if err != nil {
						if err == io.EOF {
							dm.Logger.Printf("Reached the end of file '%s' after reload.", file)
							break
						}
						dm.Logger.Errf("Error decoding JSON from file '%s' after reload: %v. Verify the file's format and content.", file, err)
						break
					}
					dm.handleContainerCreate(containerData)
				}
			}
		}
	}
}

func (dm *KubeArmorDaemon) handleContainerCreate(container tp.Container) {
	endPoint := tp.EndPoint{}

	dm.ContainersLock.Lock()
	defer dm.ContainersLock.Unlock()
	if _, ok := dm.Containers[container.ContainerID]; !ok {
		dm.Containers[container.ContainerID] = container

		// create/update endpoint in non-k8s mode
		if !dm.K8sEnabled {
			// for policy matching
			container.NamespaceName = "container_namespace"
			labels := []string{}
			labels = append(labels, "namespaceName="+container.NamespaceName)
			labels = append(labels, "kubearmor.io/container.name="+container.ContainerName)
			container.Labels = strings.Join(labels, ",")

			containerLabels, containerIdentities := kl.GetLabelsFromString(container.Labels)
			dm.EndPointsLock.Lock()
			dm.CreateEndpoint(&endPoint, container, containerLabels, containerIdentities, "ADDED")
			dm.EndPointsLock.Unlock()
		}
	} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
		c := dm.Containers[container.ContainerID]
		c.MntNS = container.MntNS
		c.PidNS = container.PidNS
		c.AppArmorProfile = container.AppArmorProfile
		dm.Containers[c.ContainerID] = c

		dm.EndPointsLock.Lock()
		for idx, endpoint := range dm.EndPoints {
			if endpoint.NamespaceName == container.NamespaceName && endpoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {

				// update apparmor profiles
				if !kl.ContainsElement(endpoint.AppArmorProfiles, container.AppArmorProfile) {
					dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, container.AppArmorProfile)
				}

				if container.Privileged && dm.EndPoints[idx].PrivilegedContainers != nil {
					dm.EndPoints[idx].PrivilegedContainers[container.ContainerName] = struct{}{}
				}

				endPoint = dm.EndPoints[idx]

				break
			}
		}
		dm.EndPointsLock.Unlock()
	}

	if len(dm.OwnerInfo) > 0 {
		container.Owner = dm.OwnerInfo[container.EndPointName]
	}

	if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
		dm.PopulateMaps(endPoint, container)
	}

	if cfg.GlobalCfg.StateAgent {
		container.Status = "running"
		go dm.StateAgent.PushContainerEvent(container, state.EventAdded)
	}

	dm.Logger.Printf("Detected a container (added/%.12s/pidns=%d/mntns=%d)", container.ContainerID, container.PidNS, container.MntNS)
}
