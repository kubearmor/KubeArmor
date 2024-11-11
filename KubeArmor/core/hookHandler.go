// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"encoding/json"
	"io"
	"log"
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
		log.Fatalln("Error opening file:", err)
	}

	decoder := json.NewDecoder(f)
	for {
		var containerData tp.Container

		err = decoder.Decode(&containerData)
		if err != nil {
			dm.Logger.Warnf("Reached EOF")
		}
		dm.handleContainerCreate(containerData)
		if err == io.EOF {
			// End of file reached
			break
		}
	}
	
	defer f.Close()

	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("Error creating new watcher:", err)
	}
	defer w.Close()

	err = w.Add(file)
	if err != nil {
		log.Fatal("Error adding file to watcher:", err)
	}

	for {
		select {
		case err, ok := <-w.Errors:
			if !ok {
				dm.Logger.Warnf("Returning 1")
				return
			}
			log.Println("Watcher error:", err)

		case e, ok := <-w.Events:
			if !ok {
				dm.Logger.Warnf("Returning 2")
				return
			}

			if e.Op&fsnotify.Write == fsnotify.Write {
				f, err := os.Open(file)
				if err != nil {
					log.Println("Error opening file:", err)
					continue
				}
				defer f.Close()

				decoder := json.NewDecoder(f)
				for {
					var containerData tp.Container

					err = decoder.Decode(&containerData)
					if err != nil {
						dm.Logger.Warnf("Reached EOF")
					}
					dm.handleContainerCreate(containerData)
					if err == io.EOF {
						// End of file reached
						break
					}
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
