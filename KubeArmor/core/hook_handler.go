// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"encoding/json"
	"io"
	"log"
	"os"

	"github.com/fsnotify/fsnotify"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func (dm *KubeArmorDaemon) HandleFile(file string) {
	dm.Logger.Warnf("Entered HandleFile")

	f, err := os.Open(file)
	if err != nil {
		log.Println("Error opening file:", err)
	}

	decoder := json.NewDecoder(f)
	for {
		var containerData types.Container

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
	f.Close()
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
				dm.Logger.Warnf("Detected changes in output.json")
				f, err := os.Open(file)
				if err != nil {
					log.Println("Error opening file:", err)
					continue
				}
				defer f.Close()

				decoder := json.NewDecoder(f)
				for {
					var containerData types.Container

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

func (dm *KubeArmorDaemon) handleContainerCreate(container types.Container) {
	endpoint := types.EndPoint{}

	dm.ContainersLock.Lock()
	defer dm.ContainersLock.Unlock()
	if _, ok := dm.Containers[container.ContainerID]; !ok {
		dm.Containers[container.ContainerID] = container
	} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
		c := dm.Containers[container.ContainerID]
		c.MntNS = container.MntNS
		c.PidNS = container.PidNS
		c.AppArmorProfile = container.AppArmorProfile
		dm.Containers[c.ContainerID] = c
		dm.EndPointsLock.Lock()
		for idx, endPoint := range dm.EndPoints {
			if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {

				// update apparmor profiles
				if !kl.ContainsElement(endPoint.AppArmorProfiles, container.AppArmorProfile) {
					dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, container.AppArmorProfile)
				}

				if container.Privileged && dm.EndPoints[idx].PrivilegedContainers != nil {
					dm.EndPoints[idx].PrivilegedContainers[container.ContainerName] = struct{}{}
				}

				endpoint = dm.EndPoints[idx]

				break
			}
		}
		dm.EndPointsLock.Unlock()
	}

	if len(dm.OwnerInfo) > 0 {
		container.Owner = dm.OwnerInfo[container.EndPointName]
	}

	if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
		dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
		dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)

		if len(endpoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endpoint yet
			dm.Logger.UpdateSecurityPolicies("ADDED", endpoint)
			if dm.RuntimeEnforcer != nil && endpoint.PolicyEnabled == types.KubeArmorPolicyEnabled {
				// enforce security policies
				dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
			}
		}
	}
}
