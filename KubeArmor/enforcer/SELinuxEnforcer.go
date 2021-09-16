// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

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

	"golang.org/x/sys/unix"
)

// ====================== //
// == SELinux Enforcer == //
// ====================== //

// SELinuxEnforcer Structure
type SELinuxEnforcer struct {
	// logs
	Logger *fd.Feeder

	SELinuxProfiles     map[string]int
	SELinuxProfilesLock *sync.Mutex

	SELinuxContextTemplates string
}

// NewSELinuxEnforcer Function
func NewSELinuxEnforcer(logger *fd.Feeder) *SELinuxEnforcer {
	se := &SELinuxEnforcer{}

	se.Logger = logger

	se.SELinuxProfiles = map[string]int{}
	se.SELinuxProfilesLock = &sync.Mutex{}

	if _, err := os.Stat("/usr/sbin/semanage"); err != nil {
		se.Logger.Errf("Failed to find /usr/sbin/semanage (%s)", err.Error())
		return nil
	}

	se.SELinuxContextTemplates = "/KubeArmor/templates/"

	if kl.IsK8sLocal() {
		if ex, err := os.Executable(); err == nil {
			se.SELinuxContextTemplates = filepath.Dir(ex) + "/templates/"
		}
	}

	// install template cil
	if err := kl.RunCommandAndWaitWithErr("semanage", []string{"module", "-a", se.SELinuxContextTemplates + "base_container.cil"}); err != nil {
		se.Logger.Errf("Failed to register a SELinux profile, %s (%s)", se.SELinuxContextTemplates+"base_container.cil", err.Error())
		return nil
	}

	return se
}

// DestroySELinuxEnforcer Function
func (se *SELinuxEnforcer) DestroySELinuxEnforcer() error {
	// skip if selinux enforcer is not active
	if se == nil {
		return nil
	}

	for profileName := range se.SELinuxProfiles {
		se.UnregisterSELinuxProfile(profileName)
	}

	// remove template cil
	if err := kl.RunCommandAndWaitWithErr("semanage", []string{"module", "-r", "base_container"}); err != nil {
		se.Logger.Errf("Failed to register a SELinux profile, %s (%s)", se.SELinuxContextTemplates+"base_container.cil", err.Error())
		return nil
	}

	return nil
}

// ================================ //
// == SELinux Profile Management == //
// ================================ //

// SELinux Flags
const (
	SELinuxDirReadOnly   = "getattr search open read lock ioctl"
	SELinuxDirReadWrite  = "getattr search open read lock ioctl setattr write link add_name remove_name reparent lock create unlink rename rmdir"
	SELinuxFileReadOnly  = "getattr ioctl lock open read"
	SELinuxFileReadWrite = "getattr ioctl lock open read write append lock create rename link unlink"
)

// DoLgetxattr is a wrapper that retries on EINTR
func DoLgetxattr(path, attr string, dest []byte) (int, error) {
	for {
		// TODO: NEED THE TERMINATION CONDITION FOR THE WORST CASE
		if sz, err := unix.Lgetxattr(path, attr, dest); err != unix.EINTR {
			return sz, err
		}
	}
}

// Lgetxattr returns a []byte slice containing the value of an extended attribute attr set for path.
func Lgetxattr(path, attr string) ([]byte, error) {
	dest := make([]byte, 128)

	sz, errno := DoLgetxattr(path, attr, dest)
	for errno == unix.ERANGE {
		// if buffer is too small, use zero-sized buffer to get the actual size
		sz, errno = DoLgetxattr(path, attr, []byte{})
		if errno != nil {
			return nil, errno
		}

		dest = make([]byte, sz)
		sz, errno = DoLgetxattr(path, attr, dest)
	}

	if errno != nil {
		return nil, errno
	}

	return dest[:sz], nil
}

// GetSELinuxType Function
func GetSELinuxType(path string) (string, error) {
	xattrNameSelinux := "security.selinux"

	label, err := Lgetxattr(path, xattrNameSelinux)
	if err != nil {
		return "", err
	}

	// Trim the NUL byte at the end of the byte buffer, if present.
	if len(label) > 0 && label[len(label)-1] == '\x00' {
		label = label[:len(label)-1]
	}

	return strings.Split(string(label), ":")[2], nil
}

// RegisterSELinuxProfile Function
func (se *SELinuxEnforcer) RegisterSELinuxProfile(containerName string, hostVolumes []tp.HostVolumeMount, profileName string) bool {
	// skip if selinux enforcer is not active
	if se == nil {
		return true
	}

	defaultProfile := "(block " + profileName + "\n" +
		"	(blockinherit container)\n" +
		// "	(blockinherit restricted_net_container)\n" +
		"	(allow process process (capability (dac_override)))\n"

	for _, hostVolume := range hostVolumes {
		if readOnly, ok := hostVolume.UsedByContainerReadOnly[containerName]; ok {
			context, err := GetSELinuxType(hostVolume.PathName)
			if err != nil {
				se.Logger.Errf("Failed to get the SELinux type of %s (%s)", hostVolume.PathName, err.Error())
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
	if _, err := os.Stat(filepath.Clean(profilePath)); err == nil {
		if err := os.Remove(filepath.Clean(profilePath)); err != nil {
			se.Logger.Err(err.Error())
			return false
		}
	}

	newFile, err := os.Create(filepath.Clean(profilePath))
	if err != nil {
		se.Logger.Err(err.Error())
		return false
	}
	if _, err := newFile.WriteString(defaultProfile); err != nil {
		se.Logger.Err(err.Error())
		return false
	}
	if err := newFile.Close(); err != nil {
		se.Logger.Err(err.Error())
	}

	if err := kl.RunCommandAndWaitWithErr("semanage", []string{"module", "-a", profilePath}); err != nil {
		se.Logger.Errf("Failed to register a SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	if _, ok := se.SELinuxProfiles[profileName]; !ok {
		se.SELinuxProfiles[profileName] = 1
		se.Logger.Errf("Registered a SELinux profile (%s)", profileName)
		return true
	}

	return false
}

// UnregisterSELinuxProfile Function
func (se *SELinuxEnforcer) UnregisterSELinuxProfile(profileName string) bool {
	// skip if selinux enforcer is not active
	if se == nil {
		return true
	}

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	profilePath := se.SELinuxContextTemplates + profileName + ".cil"

	if _, err := os.Stat(filepath.Clean(profilePath)); err != nil {
		se.Logger.Errf("Unabale to unregister a SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	if _, err := ioutil.ReadFile(filepath.Clean(profilePath)); err != nil {
		se.Logger.Errf("Unabale to unregister a SELinux profile (%s) (%s)", profileName, err.Error())
		return false
	}

	if _, ok := se.SELinuxProfiles[profileName]; !ok {
		se.Logger.Errf("Failed to unregister an unknown SELinux profile (%s) (not exist profile in the enforecer)", profileName)
		return false
	}

	if err := kl.RunCommandAndWaitWithErr("semanage", []string{"module", "-r", profileName}); err != nil {
		se.Logger.Errf("Unabale to unregister a SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	if err := os.Remove(filepath.Clean(profilePath)); err != nil {
		se.Logger.Errf("Failed to remove %s (%s)", profilePath, err.Error())
		return false
	}

	delete(se.SELinuxProfiles, profileName)

	se.Logger.Printf("Unregistered a SELinux profile (%s)", profileName)

	return true
}

// ================================= //
// == Security Policy Enforcement == //
// ================================= //

// GenerateSELinuxProfile Function
func (se *SELinuxEnforcer) GenerateSELinuxProfile(endPoint tp.EndPoint, profileName string, securityPolicies []tp.SecurityPolicy) (int, string, bool) {
	securityRules := 0

	if _, err := os.Stat(filepath.Clean(se.SELinuxContextTemplates + profileName + ".cil")); os.IsNotExist(err) {
		return 0, err.Error(), false
	}

	file, err := os.Open(filepath.Clean(se.SELinuxContextTemplates + profileName + ".cil"))
	if err != nil {
		return 0, err.Error(), false
	}

	oldProfile := ""

	fscanner := bufio.NewScanner(file)
	for fscanner.Scan() {
		line := fscanner.Text()
		oldProfile += (line + "\n")
	}
	if err := file.Close(); err != nil {
		se.Logger.Err(err.Error())
	}

	// key: container-side path, val: host-side path
	mountedPathToHostPath := map[string]string{}

	// write default volume
	newProfile := "(block " + profileName + "\n" +
		"	(blockinherit container)\n" +
		// "	(blockinherit restricted_net_container)\n" +
		"	(allow process process (capability (dac_override)))\n"

	found := false

	for _, hostVolume := range endPoint.HostVolumes {
		for containerName := range hostVolume.UsedByContainerPath {
			if !strings.Contains(profileName, containerName) {
				continue
			}

			found = true

			if readOnly, ok := hostVolume.UsedByContainerReadOnly[containerName]; ok {
				mountedPathToHostPath[hostVolume.UsedByContainerPath[containerName]] = hostVolume.PathName

				context, err := GetSELinuxType(hostVolume.PathName)
				if err != nil {
					se.Logger.Errf("Failed to get the SELinux type of %s (%s)", hostVolume.PathName, err.Error())
					return 0, "", false
				}

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

		if !found {
			return 0, "", false
		}

		// write policy volume
		for _, policy := range securityPolicies {
			for _, vol := range policy.Spec.SELinux.MatchVolumeMounts {
				// file
				if len(vol.Path) > 0 {
					absolutePath := vol.Path
					readOnly := vol.ReadOnly

					for containerPath, hostPath := range mountedPathToHostPath {
						if strings.Contains(absolutePath, containerPath) {
							filePath := strings.Split(absolutePath, containerPath)[1]
							hostAbsolutePath := hostPath + filePath

							if context, err := GetSELinuxType(hostAbsolutePath); err != nil {
								se.Logger.Errf("Failed to get the SELinux type of %s (%s)", hostVolume.PathName, err.Error())
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

							if context, err := GetSELinuxType(hostAbsolutePath); err != nil {
								se.Logger.Errf("Failed to get the SELinux type of %s (%s)", hostVolume.PathName, err.Error())
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
func (se *SELinuxEnforcer) UpdateSELinuxProfile(endPoint tp.EndPoint, seLinuxProfile string, securityPolicies []tp.SecurityPolicy) {
	// skip if selinux enforcer is not active
	if se == nil {
		return
	}

	if ruleCount, newProfile, ok := se.GenerateSELinuxProfile(endPoint, seLinuxProfile, securityPolicies); ok {
		newfile, err := os.Create(filepath.Clean(se.SELinuxContextTemplates + seLinuxProfile + ".cil"))
		if err != nil {
			se.Logger.Err(err.Error())
			return
		}
		defer func() {
			if err := newfile.Close(); err != nil {
				se.Logger.Err(err.Error())
			}
		}()

		if _, err := newfile.WriteString(newProfile); err != nil {
			se.Logger.Err(err.Error())
			return
		}

		if err := newfile.Sync(); err != nil {
			se.Logger.Err(err.Error())
			return
		}

		if err := kl.RunCommandAndWaitWithErr("semanage", []string{"module", "-a", se.SELinuxContextTemplates + seLinuxProfile + ".cil"}); err == nil {
			se.Logger.Printf("Updated %d security rule(s) to %s/%s/%s", ruleCount, endPoint.NamespaceName, endPoint.EndPointName, seLinuxProfile)
		} else {
			se.Logger.Errf("Failed to update %d security rule(s) to %s/%s/%s (%s)", ruleCount, endPoint.NamespaceName, endPoint.EndPointName, seLinuxProfile, err.Error())
		}
	}
}

// UpdateSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if selinux enforcer is not active
	if se == nil {
		return
	}

	selinuxProfiles := []string{}

	for _, seLinuxProfile := range endPoint.SELinuxProfiles {
		if !kl.ContainsElement(selinuxProfiles, seLinuxProfile) {
			selinuxProfiles = append(selinuxProfiles, seLinuxProfile)
		}
	}

	for _, selinuxProfile := range selinuxProfiles {
		se.UpdateSELinuxProfile(endPoint, selinuxProfile, endPoint.SecurityPolicies)
	}
}

// ====================================== //
// == Host Security Policy Enforcement == //
// ====================================== //

// UpdateHostSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if selinux enforcer is not active
	if se == nil {
		return
	}

	//
}
