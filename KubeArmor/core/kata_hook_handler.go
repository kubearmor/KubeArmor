// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/state"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

var (
	kataHookWaitTimeout  = 30 * time.Second
	kataHookPollInterval = 500 * time.Millisecond
)

// HandleContainerCreateForKata registers or completes a Kata container entry.
func (dm *KubeArmorDaemon) HandleContainerCreateForKata(container tp.Container) bool {
	// Skip invalid entries or containers whose namespaces haven't both been resolved yet
	if container.ContainerID == "" || container.PidNS == 0 || container.MntNS == 0 {
		return false
	}

	// Guard against path traversal in AppArmor profile names
	if container.AppArmorProfile != "" &&
		(strings.Contains(container.AppArmorProfile, "/") ||
			strings.Contains(container.AppArmorProfile, "\\") ||
			strings.Contains(container.AppArmorProfile, "..")) {
		dm.Logger.Warnf("Ignoring invalid AppArmor profile %q for container %.12s", container.AppArmorProfile, container.ContainerID)
		container.AppArmorProfile = ""
	}

	endPoint := tp.EndPoint{}

	dm.ContainersLock.Lock()
	if existing, ok := dm.Containers[container.ContainerID]; !ok {
		if !dm.K8sEnabled {
			// create/update endpoint in non-k8s mode
			container.NamespaceName = "container_namespace"
			labels := []string{
				"namespaceName=" + container.NamespaceName,
				"kubearmor.io/container.name=" + container.ContainerName,
			}
			container.Labels = strings.Join(labels, ",")

			containerLabels, containerIdentities := kl.GetLabelsFromString(container.Labels)
			dm.EndPointsLock.Lock()
			dm.CreateEndpoint(&endPoint, container, containerLabels, containerIdentities, "ADDED")
			dm.EndPointsLock.Unlock()
		} else if container.NamespaceName == "" {
			// Match HandleUnknownNamespaceNsMap in kubeUpdate.go when hook fires before Pod informer
			container.NamespaceName = "Unknown"
		} else if container.EndPointName != "" && container.ContainerName != "" {
			// Re-link restarted Kata containers to their existing EndPoint before Pod MODIFIED arrives
			dm.EndPointsLock.Lock()
			for idx, ep := range dm.EndPoints {
				if ep.NamespaceName == container.NamespaceName &&
					ep.EndPointName == container.EndPointName &&
					ep.ContainerName == container.ContainerName {
					dm.EndPoints[idx].Containers = []string{container.ContainerID}
					if container.AppArmorProfile != "" &&
						!kl.ContainsElement(ep.AppArmorProfiles, container.AppArmorProfile) {
						dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, container.AppArmorProfile)
					}
					container.PolicyEnabled = ep.PolicyEnabled
					container.ProcessVisibilityEnabled = ep.ProcessVisibilityEnabled
					container.FileVisibilityEnabled = ep.FileVisibilityEnabled
					container.NetworkVisibilityEnabled = ep.NetworkVisibilityEnabled
					container.CapabilitiesVisibilityEnabled = ep.CapabilitiesVisibilityEnabled
					endPoint = dm.EndPoints[idx]
					break
				}
			}
			dm.EndPointsLock.Unlock()
		}
		dm.Containers[container.ContainerID] = container
	} else if existing.PidNS == 0 || existing.MntNS == 0 {
		existing.MntNS = container.MntNS
		existing.PidNS = container.PidNS
		if container.AppArmorProfile != "" {
			existing.AppArmorProfile = container.AppArmorProfile
		}
		dm.Containers[existing.ContainerID] = existing
		container = existing

		dm.EndPointsLock.Lock()
		for idx, endpoint := range dm.EndPoints {
			if endpoint.NamespaceName == existing.NamespaceName &&
				endpoint.EndPointName == existing.EndPointName &&
				kl.ContainsElement(endpoint.Containers, existing.ContainerID) {

				if existing.AppArmorProfile != "" &&
					!kl.ContainsElement(endpoint.AppArmorProfiles, existing.AppArmorProfile) {
					dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, existing.AppArmorProfile)
				}

				endPoint = dm.EndPoints[idx]
				break
			}
		}
		dm.EndPointsLock.Unlock()
	} else {
		// Already registered with valid PidNS/MntNS; ignore duplicate snapshot reads
		dm.ContainersLock.Unlock()
		return false
	}
	dm.ContainersLock.Unlock()

	dm.OwnerInfoLock.RLock()
	if len(dm.OwnerInfo) > 0 {
		container.Owner = dm.OwnerInfo[container.EndPointName]
	}
	dm.OwnerInfoLock.RUnlock()

	if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
		dm.PopulateMaps(endPoint, container)
	}

	if cfg.GlobalCfg.StateAgent && dm.StateAgent != nil {
		container.Status = "running"
		go dm.StateAgent.PushContainerEvent(container, state.EventAdded)
	}

	dm.Logger.Printf("Detected a container (added/%.12s/pidns=%d/mntns=%d)", container.ContainerID, container.PidNS, container.MntNS)
	return true
}

func (dm *KubeArmorDaemon) HandleContainerDeleteForKata(containerID string) {
	dm.ContainersLock.Lock()
	container, ok := dm.Containers[containerID]
	if !ok {
		dm.ContainersLock.Unlock()
		return
	}
	delete(dm.Containers, containerID)

	if !dm.K8sEnabled {
		dm.EndPointsLock.Lock()
		for idx, endpoint := range dm.EndPoints {
			if kl.ContainsElement(endpoint.Containers, containerID) {
				dm.EndPoints[idx].Containers = slices.DeleteFunc(
					dm.EndPoints[idx].Containers,
					func(id string) bool { return id == containerID },
				)
				if len(dm.EndPoints[idx].SecurityPolicies) == 0 && len(dm.EndPoints[idx].Containers) == 0 {
					dm.EndPoints = slices.Delete(dm.EndPoints, idx, idx+1)
				}
				break
			}
		}
		dm.EndPointsLock.Unlock()
	} else {
		dm.EndPointsLock.Lock()
		for idx, endpoint := range dm.EndPoints {
			if endpoint.NamespaceName == container.NamespaceName &&
				endpoint.EndPointName == container.EndPointName &&
				kl.ContainsElement(endpoint.Containers, containerID) {
				if container.AppArmorProfile != "" {
					dm.EndPoints[idx].AppArmorProfiles = slices.DeleteFunc(
						dm.EndPoints[idx].AppArmorProfiles,
						func(p string) bool { return p == container.AppArmorProfile },
					)
				}
				break
			}
		}
		dm.EndPointsLock.Unlock()
	}
	dm.ContainersLock.Unlock()

	if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
		dm.SystemMonitor.Logger.ContainerNsKeyLock.Lock()
		outkey, exists := dm.SystemMonitor.Logger.ContainerNsKey[containerID]
		if exists {
			delete(dm.SystemMonitor.Logger.ContainerNsKey, containerID)
		}
		dm.SystemMonitor.Logger.ContainerNsKeyLock.Unlock()

		if exists {
			dm.Logger.DeleteAlertMapKey(outkey)
		}

		dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
		if dm.RuntimeEnforcer != nil {
			dm.RuntimeEnforcer.UnregisterContainer(containerID)
		}
		if dm.Presets != nil {
			dm.Presets.UnregisterContainer(containerID)
		}
	}

	if cfg.GlobalCfg.StateAgent && dm.StateAgent != nil {
		container.Status = "terminated"
		go dm.StateAgent.PushContainerEvent(container, state.EventDeleted)
	}

	dm.Logger.Printf("Detected a container (removed/%.12s/pidns=%d/mntns=%d)", containerID, container.PidNS, container.MntNS)
}

func (dm *KubeArmorDaemon) waitForKataHookFile(cleanFile string) bool {
	if _, err := os.Stat(cleanFile); err == nil {
		return true
	} else if !errors.Is(err, os.ErrNotExist) {
		dm.Logger.Errf("Failed to stat Kata hook file '%s': %v", cleanFile, err)
		return false
	}

	dm.Logger.Warnf("Kata hook file '%s' not found yet; waiting up to %s", cleanFile, kataHookWaitTimeout)

	timeout := time.NewTimer(kataHookWaitTimeout)
	defer timeout.Stop()

	ticker := time.NewTicker(kataHookPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-StopChan:
			return false

		case <-timeout.C:
			dm.Logger.Errf("Kata hook file '%s' not found after %s; verify OCI hook setup and output path", cleanFile, kataHookWaitTimeout)
			return false

		case <-ticker.C:
			if _, err := os.Stat(cleanFile); err == nil {
				return true
			} else if !errors.Is(err, os.ErrNotExist) {
				dm.Logger.Errf("Failed to stat Kata hook file '%s': %v", cleanFile, err)
				return false
			}
		}
	}
}

func (dm *KubeArmorDaemon) WatchKataHookFile(file string) {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	if strings.TrimSpace(file) == "" {
		dm.Logger.Errf("Kata hook file path is empty")
		return
	}

	cleanFile := filepath.Clean(file)
	if !dm.waitForKataHookFile(cleanFile) {
		return
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		dm.Logger.Errf("Failed to create fsnotify watcher for '%s': %v", cleanFile, err)
		return
	}
	defer w.Close()

	// Add watcher before the initial read so updates during startup aren't missed
	dir := filepath.Dir(cleanFile)
	if err := w.Add(dir); err != nil {
		dm.Logger.Errf("Failed to watch Kata hook directory '%s': %v", dir, err)
		return
	}

	activeContainers := make(map[string]struct{})
	if err := dm.processKataHookFile(cleanFile, activeContainers); err != nil {
		dm.Logger.Errf("Error processing Kata hook file '%s': %v", cleanFile, err)
	}

	for {
		select {
		case <-StopChan:
			return

		case err, ok := <-w.Errors:
			if !ok {
				dm.Logger.Warnf("Kata hook watcher error channel closed; exiting")
				return
			}
			dm.Logger.Errf("Kata hook watcher error: %v", err)

		case e, ok := <-w.Events:
			if !ok {
				dm.Logger.Warnf("Kata hook watcher event channel closed; exiting")
				return
			}

			if filepath.Clean(e.Name) != cleanFile {
				continue
			}

			if e.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if err := dm.processKataHookFile(cleanFile, activeContainers); err != nil {
					dm.Logger.Errf("Error processing Kata hook file '%s': %v", cleanFile, err)
				}
			}
		}
	}
}
func (dm *KubeArmorDaemon) processKataHookFile(file string, activeContainers map[string]struct{}) error {
	data, err := os.ReadFile(filepath.Clean(file)) // #nosec G304
	if err != nil {
		return err
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		// Skip empty reads instead of wiping activeContainers; an explicit "{}" clears them
		return nil
	}

	snapshot := make(map[string]tp.Container)
	if err := json.Unmarshal(trimmed, &snapshot); err != nil {
		return err
	}

	seen := make(map[string]tp.Container, len(snapshot))

	for id, containerData := range snapshot {
		if containerData.ContainerID == "" {
			containerData.ContainerID = id
		}
		cid := containerData.ContainerID
		if cid == "" {
			continue
		}
		if containerData.PidNS == 0 && containerData.MntNS == 0 {
			continue
		}
		seen[cid] = containerData
	}

	for id := range activeContainers {
		if _, exists := seen[id]; !exists {
			dm.HandleContainerDeleteForKata(id)
			delete(activeContainers, id)
		}
	}

	for cid, containerData := range seen {
		// Skip containers already tracked to avoid re-running create on every snapshot update
		if _, tracked := activeContainers[cid]; tracked {
			continue
		}
		if dm.HandleContainerCreateForKata(containerData) {
			activeContainers[cid] = struct{}{}
		}
	}

	return nil
}
