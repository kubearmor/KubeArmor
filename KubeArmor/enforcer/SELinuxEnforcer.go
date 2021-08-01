// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package enforcer

import (
	"bufio"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ====================== //
// == SELinux Enforcer == //
// ====================== //

// SELinuxEnforcer Structure
type SELinuxEnforcer struct {
	// logs
	LogFeeder *fd.Feeder

	SELinuxProfiles     map[string]int
	SELinuxProfilesLock *sync.Mutex

	SELinuxContextTemplates string
}

// NewSELinuxEnforcer Function
func NewSELinuxEnforcer(feeder *fd.Feeder) *SELinuxEnforcer {
	se := &SELinuxEnforcer{}

	se.LogFeeder = feeder

	se.SELinuxProfiles = map[string]int{}
	se.SELinuxProfilesLock = &sync.Mutex{}

	if _, err := os.Stat("/usr/sbin/semanage"); err != nil {
		se.LogFeeder.Errf("Failed to find /usr/sbin/semanage (%s)", err.Error())
		return nil
	}

	se.SELinuxContextTemplates = "/KubeArmor/templates/"

	if kl.IsK8sLocal() {
		if ex, err := os.Executable(); err == nil {
			se.SELinuxContextTemplates = filepath.Dir(ex) + "/templates/"
		}
	}

	// install template cil
	if output, err := kl.GetCommandOutputWithErr("semanage", []string{"module", "-a", se.SELinuxContextTemplates + "base_container.cil"}); err != nil {
		se.LogFeeder.Printf("Failed to register a SELinux profile (%s) (%s, %s)", se.SELinuxContextTemplates+"base_container.cil", output, err.Error())
		return nil
	}

	return se
}

// DestroySELinuxEnforcer Function
func (se *SELinuxEnforcer) DestroySELinuxEnforcer() error {
	for profileName := range se.SELinuxProfiles {
		emptyPod := tp.K8sPod{Metadata: map[string]string{}}
		se.UnregisterSELinuxProfile(emptyPod, profileName)
	}

	// remove template cil
	if output, err := kl.GetCommandOutputWithErr("semanage", []string{"module", "-r", "base_container"}); err != nil {
		se.LogFeeder.Printf("Failed to register a SELinux profile (%s) (%s, %s)", se.SELinuxContextTemplates+"base_container.cil", output, err.Error())
		return nil
	}

	return nil
}

// ================================ //
// == SELinux Profile Management == //
// ================================ //

const (
	SELinuxDirReadOnly   = "getattr search open read lock ioctl"
	SELinuxDirReadWrite  = "getattr search open read lock ioctl setattr write link add_name remove_name reparent lock create unlink rename rmdir"
	SELinuxFileReadOnly  = "getattr ioctl lock open read"
	SELinuxFileReadWrite = "getattr ioctl lock open read write append lock create rename link unlink"
)

// RegisterSELinuxProfile Function
func (se *SELinuxEnforcer) RegisterSELinuxProfile(pod tp.K8sPod, containerName, profileName string) bool {
	namespace := pod.Metadata["namespaceName"]
	podName := pod.Metadata["podName"]

	defaultProfile := "(block " + profileName + "\n" +
		"	(blockinherit container)\n" +
		// "	(blockinherit restricted_net_container)\n" +
		"	(allow process process (capability (dac_override)))\n"

	for _, hostVolume := range pod.HostVolumes {
		if readOnly, ok := hostVolume.UsedByContainerReadOnly[containerName]; ok {
			context, err := kl.GetSELinuxType(hostVolume.PathName)
			if err != nil {
				se.LogFeeder.Errf("Failed to get the SELinux type of %s (%s)", hostVolume.PathName, err.Error())
				return false
			}

			contextLine := "	(allow process " + context

			if readOnly {
				if hostVolume.Type == "Directory" {
					contextDirLine := contextLine + " (dir (" + SELinuxDirReadOnly + ")))\n"
					defaultProfile = defaultProfile + contextDirLine
				} else {
					contextFileLine := contextLine + " (file (" + SELinuxFileReadOnly + ")))\n"
					defaultProfile = defaultProfile + contextFileLine
				}
			} else {
				if hostVolume.Type == "Directory" {
					contextDirLine := contextLine + " (dir (" + SELinuxDirReadWrite + ")))\n"
					defaultProfile = defaultProfile + contextDirLine
				} else {
					contextFileLine := contextLine + " (file (" + SELinuxFileReadWrite + ")))\n"
					defaultProfile = defaultProfile + contextFileLine
				}
			}
		}
	}
	defaultProfile = defaultProfile + ")\n"

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	profilePath := se.SELinuxContextTemplates + profileName + ".cil"
	if _, err := os.Stat(profilePath); err == nil {
		if err := os.Remove(profilePath); err != nil {
			se.LogFeeder.Err(err.Error())
			return false
		}
	}

	newFile, err := os.Create(profilePath)
	if err != nil {
		se.LogFeeder.Err(err.Error())
		return false
	}
	if _, err := newFile.WriteString(defaultProfile); err != nil {
		se.LogFeeder.Err(err.Error())
		return false
	}
	newFile.Close()

	output, err := kl.GetCommandOutputWithErr("semanage", []string{"module", "-a", profilePath})
	if err != nil {
		se.LogFeeder.Printf("Failed to register a SELinux profile (%s) for (%s/%s) (%s, %s)", profileName, namespace, podName, output, err.Error())
		return false
	}

	if _, ok := se.SELinuxProfiles[profileName]; !ok {
		se.SELinuxProfiles[profileName] = 1
		se.LogFeeder.Printf("Registered a SELinux profile (%s) for (%s/%s)", profileName, namespace, podName)
		return true
	}

	return false
}

// UnregisterSELinuxProfile Function
func (se *SELinuxEnforcer) UnregisterSELinuxProfile(pod tp.K8sPod, profileName string) bool {
	namespace := pod.Metadata["namespaceName"]
	podName := pod.Metadata["podName"]

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	profilePath := se.SELinuxContextTemplates + profileName + ".cil"

	if _, err := os.Stat(profilePath); err != nil {
		se.LogFeeder.Printf("Unabale to unregister a SELinux profile (%s) for (%s/%s) (%s)", profileName, namespace, podName, err.Error())
		return false
	}

	if _, err := ioutil.ReadFile(profilePath); err != nil {
		if namespace == "" || podName == "" {
			se.LogFeeder.Printf("Unabale to unregister a SELinux profile (%s) (%s)", profileName, err.Error())
		} else {
			se.LogFeeder.Printf("Unabale to unregister a SELinux profile (%s) for (%s/%s) (%s)", profileName, namespace, podName, err.Error())
		}
		return false
	}

	referenceCount, ok := se.SELinuxProfiles[profileName]

	if !ok {
		if namespace == "" || podName == "" {
			se.LogFeeder.Printf("Failed to unregister an unknown SELinux profile (%s) (not exist profile in the enforecer)", profileName)
		} else {
			se.LogFeeder.Printf("Failed to unregister an unknown SELinux profile (%s) for (%s/%s) (not exist profile in the enforecer)", profileName, namespace, podName)
		}
		return false
	}

	if referenceCount > 1 {
		se.SELinuxProfiles[profileName]--
		se.LogFeeder.Printf("Decreased the refCount (%d -> %d) of a SELinux profile (%s)", se.SELinuxProfiles[profileName]+1, se.SELinuxProfiles[profileName], profileName)
	} else {
		if output, err := kl.GetCommandOutputWithErr("semanage", []string{"module", "-r", profileName}); err != nil {
			if namespace == "" || podName == "" {
				se.LogFeeder.Printf("Unabale to unregister a SELinux profile (%s) (%s, %s)", profileName, output, err.Error())
			} else {
				se.LogFeeder.Printf("Unabale to unregister a SELinux profile (%s) for (%s/%s) (%s, %s)", profileName, namespace, podName, output, err.Error())
			}
			return false
		}

		if err := os.Remove(profilePath); err != nil {
			se.LogFeeder.Errf("Failed to remove %s (%s)", profilePath, err.Error())
			return false
		}

		delete(se.SELinuxProfiles, profileName)

		if namespace == "" || podName == "" {
			se.LogFeeder.Printf("Unregistered a SELinux profile (%s)", profileName)
		} else {
			se.LogFeeder.Printf("Unregistered a SELinux profile (%s) for (%s/%s)", profileName, namespace, podName)
		}
	}

	return true
}

// ================================= //
// == Security Policy Enforcement == //
// ================================= //

// GenerateSELinuxProfile Function
func (se *SELinuxEnforcer) GenerateSELinuxProfile(pod tp.ContainerGroup, profileName string, securityPolicies []tp.SecurityPolicy) (int, string, bool) {
	securityRules := 0

	if _, err := os.Stat(se.SELinuxContextTemplates + profileName + ".cil"); os.IsNotExist(err) {
		return 0, err.Error(), false
	}

	file, err := os.Open(se.SELinuxContextTemplates + profileName + ".cil")
	if err != nil {
		return 0, err.Error(), false
	}

	oldProfile := ""

	fscanner := bufio.NewScanner(file)
	for fscanner.Scan() {
		line := fscanner.Text()
		oldProfile += (line + "\n")
	}
	file.Close()

	// key: container-side path, val: host-side path
	mountedPathToHostPath := map[string]string{}

	// write default volume
	newProfile := "(block " + profileName + "\n" +
		"	(blockinherit container)\n" +
		// "	(blockinherit restricted_net_container)\n" +
		"	(allow process process (capability (dac_override)))\n"

	found := false

	for _, hostVolume := range pod.HostVolumes {
		for containerName := range hostVolume.UsedByContainerPath {
			if !strings.Contains(profileName, containerName) {
				continue
			}

			found = true

			if readOnly, ok := hostVolume.UsedByContainerReadOnly[containerName]; ok {
				mountedPathToHostPath[hostVolume.UsedByContainerPath[containerName]] = hostVolume.PathName

				if context, err := kl.GetSELinuxType(hostVolume.PathName); err != nil {
					se.LogFeeder.Errf("Failed to get the SELinux type of %s (%s)", hostVolume.PathName, err.Error())
					return 0, "", false
				} else {
					contextLine := "	(allow process " + context

					if readOnly {
						contextDirLine := contextLine + " (dir (" + SELinuxDirReadOnly + ")))\n"
						contextFileLine := contextLine + " (file (" + SELinuxFileReadOnly + ")))\n"
						newProfile = newProfile + contextDirLine + contextFileLine
					} else {
						contextDirLine := contextLine + " (dir (" + SELinuxDirReadWrite + ")))\n"
						contextFileLine := contextLine + " (file (" + SELinuxFileReadWrite + ")))\n"
						newProfile = newProfile + contextDirLine + contextFileLine
					}
				}
			}
		}

		if !found {
			return 0, "", false
		}

		// write policy volume
		for _, policy := range securityPolicies {
			for _, vol := range policy.Spec.SELinux.MatchMountedVolumes {
				// file
				if len(vol.Path) > 0 {
					absolutePath := vol.Path
					readOnly := vol.ReadOnly

					for containerPath, hostPath := range mountedPathToHostPath {
						if strings.Contains(absolutePath, containerPath) {
							filePath := strings.Split(absolutePath, containerPath)[1]
							hostAbsolutePath := hostPath + filePath

							if context, err := kl.GetSELinuxType(hostAbsolutePath); err != nil {
								se.LogFeeder.Errf("Failed to get the SELinux type of %s (%s)", hostVolume.PathName, err.Error())
								break
							} else {
								contextLine := "	(allow process " + context

								if readOnly {
									contextFileLine := contextLine + " (file (" + SELinuxFileReadOnly + ")))\n"
									newProfile = newProfile + contextFileLine
									securityRules++
								} else {
									contextFileLine := contextLine + " (file (" + SELinuxFileReadWrite + ")))\n"
									newProfile = newProfile + contextFileLine
									securityRules++
								}
							}
						}
					}
				}

				// directory
				if len(vol.Directory) > 0 {
					absolutePath := vol.Directory
					readOnly := vol.ReadOnly

					for containerPath, hostPath := range mountedPathToHostPath {
						if strings.Contains(absolutePath, containerPath) {
							filePath := strings.Split(absolutePath, containerPath)[1]
							hostAbsolutePath := hostPath + filePath

							if context, err := kl.GetSELinuxType(hostAbsolutePath); err != nil {
								se.LogFeeder.Errf("Failed to get the SELinux type of %s (%s)", hostVolume.PathName, err.Error())
								break
							} else {
								contextLine := "	(allow process " + context

								if readOnly {
									contextDirLine := contextLine + " (dir (" + SELinuxDirReadOnly + ")))\n"
									newProfile = newProfile + contextDirLine
									securityRules++
								} else {
									contextDirLine := contextLine + " (dir (" + SELinuxDirReadWrite + ")))\n"
									newProfile = newProfile + contextDirLine
									securityRules++
								}
							}
						}
					}
				}
			}
		}
	}

	newProfile = newProfile + ")\n"

	if newProfile != oldProfile {
		return securityRules, newProfile, true
	}

	return 0, "", false
}

// UpdateSELinuxProfile Function
func (se *SELinuxEnforcer) UpdateSELinuxProfile(conGroup tp.ContainerGroup, seLinuxProfile string, securityPolicies []tp.SecurityPolicy) {
	if ruleCount, newProfile, ok := se.GenerateSELinuxProfile(conGroup, seLinuxProfile, securityPolicies); ok {
		newfile, err := os.Create(se.SELinuxContextTemplates + seLinuxProfile + ".cil")
		if err != nil {
			se.LogFeeder.Err(err.Error())
			return
		}
		defer newfile.Close()

		if _, err := newfile.WriteString(newProfile); err != nil {
			se.LogFeeder.Err(err.Error())
			return
		}

		if err := newfile.Sync(); err != nil {
			se.LogFeeder.Err(err.Error())
			return
		}

		if output, err := kl.GetCommandOutputWithErr("semanage", []string{"module", "-a", se.SELinuxContextTemplates + seLinuxProfile + ".cil"}); err == nil {
			se.LogFeeder.Printf("Updated %d security rule(s) to %s/%s/%s", ruleCount, conGroup.NamespaceName, conGroup.ContainerGroupName, seLinuxProfile)
		} else {
			se.LogFeeder.Printf("Failed to update %d security rule(s) to %s/%s/%s (%s)", ruleCount, conGroup.NamespaceName, conGroup.ContainerGroupName, seLinuxProfile, output)
		}
	}
}

// UpdateSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	selinuxProfiles := []string{}

	for _, seLinuxProfile := range conGroup.SELinuxProfiles {
		if !kl.ContainsElement(selinuxProfiles, seLinuxProfile) {
			selinuxProfiles = append(selinuxProfiles, seLinuxProfile)
		}
	}

	for _, selinuxProfile := range selinuxProfiles {
		se.UpdateSELinuxProfile(conGroup, selinuxProfile, conGroup.SecurityPolicies)
	}
}

// ====================================== //
// == Host Security Policy Enforcement == //
// ====================================== //

// UpdateHostSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	//
}
