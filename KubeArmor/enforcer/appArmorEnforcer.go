// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package enforcer

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ======================= //
// == AppArmor Enforcer == //
// ======================= //

// AppArmorEnforcer Structure
type AppArmorEnforcer struct {
	// host name
	HostName string

	// logs
	Logger *fd.Feeder

	// options
	EnableHostPolicy bool

	// host profile
	HostProfile string

	// profiles for containers
	AppArmorProfiles     map[string]int
	AppArmorProfilesLock *sync.Mutex
}

// NewAppArmorEnforcer Function
func NewAppArmorEnforcer(feeder *fd.Feeder, enableHostPolicy bool) *AppArmorEnforcer {
	ae := &AppArmorEnforcer{}

	// host name
	ae.HostName = kl.GetHostName()

	// logs
	ae.Logger = feeder

	// options
	ae.EnableHostPolicy = enableHostPolicy

	// host profile
	ae.HostProfile = ""

	// profiles
	ae.AppArmorProfiles = map[string]int{}
	ae.AppArmorProfilesLock = &sync.Mutex{}

	files, err := ioutil.ReadDir("/etc/apparmor.d")
	if err != nil {
		ae.Logger.Errf("Failed to read /etc/apparmor.d (%s)", err.Error())
		return nil
	}

	existingProfiles := []string{}

	if pids, err := ioutil.ReadDir(filepath.Clean("/proc")); err == nil {
		for _, f := range pids {
			if f.IsDir() {
				if _, err := strconv.Atoi(f.Name()); err == nil {
					if content, err := ioutil.ReadFile(filepath.Clean("/proc/" + f.Name() + "/attr/current")); err == nil {
						line := strings.Split(string(content), "\n")[0]
						words := strings.Split(line, " ")

						// check if there are KubeArmor's profiles used by containers
						if !kl.ContainsElement(existingProfiles, words[0]) {
							existingProfiles = append(existingProfiles, words[0])
						}
					}
				}
			}
		}
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		fileName := file.Name()

		data, err := ioutil.ReadFile(filepath.Clean("/etc/apparmor.d/" + fileName))
		if err != nil {
			ae.Logger.Errf("Failed to read /etc/apparmor.d/%s (%s)", fileName, err.Error())
			continue
		}

		str := string(data)

		if strings.Contains(str, "KubeArmor") {
			if kl.ContainsElement(existingProfiles, fileName) {
				continue // if the profile is used by a running container, do not remove it
			}

			if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-R", "/etc/apparmor.d/" + fileName}); err != nil {
				ae.Logger.Errf("Failed to detach /etc/apparmor.d/%s (%s)", fileName, err.Error())
				continue // still need to check other profiles
			}

			if err := os.Remove(filepath.Clean("/etc/apparmor.d/" + fileName)); err != nil {
				ae.Logger.Errf("Failed to remove /etc/apparmor.d/%s (%s)", fileName, err.Error())
				continue // still need to check other profiles
			}

			ae.Logger.Printf("Removed an inactive AppArmor profile (%s)", fileName)
		}
	}

	if ae.EnableHostPolicy {
		if ok := ae.RegisterAppArmorHostProfile(); !ok {
			return nil
		}
	}

	return ae
}

// DestroyAppArmorEnforcer Function
func (ae *AppArmorEnforcer) DestroyAppArmorEnforcer() error {
	if ae.EnableHostPolicy {
		ae.UnregisterAppArmorHostProfile()
	}

	return nil
}

// ================================= //
// == AppArmor Profile Management == //
// ================================= //

// RegisterAppArmorProfile Function
func (ae *AppArmorEnforcer) RegisterAppArmorProfile(profileName string, full bool) bool {
	apparmorDefault := "## == Managed by KubeArmor == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile apparmor-default flags=(attach_disconnected,mediate_deleted) {\n" +
		"  ## == PRE START == ##\n" +
		"  #include <abstractions/base>\n" +
		"  umount,\n" +
		"  file,\n" +
		"  network,\n" +
		"  capability,\n" +
		"  ## == PRE END == ##\n" +
		"\n" +
		"  ## == POLICY START == ##\n" +
		"  ## == POLICY END == ##\n" +
		"\n" +
		"  ## == POST START == ##\n" +
		"  /lib/x86_64-linux-gnu/{*,**} r,\n" +
		"\n" +
		"  deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,\n" +
		"  deny @{PROC}/sysrq-trigger rwklx,\n" +
		"  deny @{PROC}/mem rwklx,\n" +
		"  deny @{PROC}/kmem rwklx,\n" +
		"  deny @{PROC}/kcore rwklx,\n" +
		"\n" +
		"  deny mount,\n" +
		"\n" +
		"  deny /sys/[^f]*/** wklx,\n" +
		"  deny /sys/f[^s]*/** wklx,\n" +
		"  deny /sys/fs/[^c]*/** wklx,\n" +
		"  deny /sys/fs/c[^g]*/** wklx,\n" +
		"  deny /sys/fs/cg[^r]*/** wklx,\n" +
		"  deny /sys/firmware/efi/efivars/** rwklx,\n" +
		"  deny /sys/kernel/security/** rwklx,\n" +
		"  ## == POST END == ##\n" +
		"}\n"

	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

	if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + profileName)); err == nil {
		content, err := ioutil.ReadFile(filepath.Clean("/etc/apparmor.d/" + profileName))
		if err != nil {
			if full {
				ae.Logger.Printf("Unable to register an AppArmor profile (%s, %s)", profileName, err.Error())
			} else {
				ae.Logger.Printf("Unable to read the existing AppArmor profile (%s, %s)", profileName, err.Error())
			}
			return false
		}

		if !strings.Contains(string(content), "KubeArmor") {
			if full {
				ae.Logger.Printf("Unable to register an AppArmor profile (%s) (out-of-control)", profileName)
			} else {
				ae.Logger.Printf("Unable to control the existing AppArmor profile (%s) (out-of-control)", profileName)
			}
			return false
		}
	} else {
		newProfile := strings.Replace(apparmorDefault, "apparmor-default", profileName, -1)

		newFile, err := os.Create(filepath.Clean("/etc/apparmor.d/" + profileName))
		if err != nil {
			ae.Logger.Err(err.Error())
			return false
		}
		defer func() {
			if err := newFile.Close(); err != nil {
				ae.Logger.Err(err.Error())
			}
		}()

		if _, err := newFile.WriteString(newProfile); err != nil {
			ae.Logger.Err(err.Error())
			return false
		}
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + profileName}); err == nil {
		if full {
			if _, ok := ae.AppArmorProfiles[profileName]; !ok {
				ae.AppArmorProfiles[profileName] = 1
				ae.Logger.Printf("Registered an AppArmor profile (%s)", profileName)
			} else {
				ae.AppArmorProfiles[profileName]++
				ae.Logger.Printf("Registered an AppArmor profile (%s, refCount: %d)", profileName, ae.AppArmorProfiles[profileName])
			}
		} else {
			delete(ae.AppArmorProfiles, profileName)
			ae.Logger.Printf("Initialize an AppArmor profile (%s)", profileName)
		}
	} else {
		if full {
			ae.Logger.Printf("Failed to register an AppArmor profile (%s, %s)", profileName, err.Error())
		} else {
			ae.Logger.Printf("Failed to initialize an AppArmor profile (%s, %s)", profileName, err.Error())
		}
		return false
	}

	return true
}

// UnregisterAppArmorProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorProfile(profileName string, full bool) bool {
	if full {
		ae.AppArmorProfilesLock.Lock()
		defer ae.AppArmorProfilesLock.Unlock()

		if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + profileName)); err == nil {
			content, err := ioutil.ReadFile(filepath.Clean("/etc/apparmor.d/" + profileName))
			if err != nil {
				ae.Logger.Printf("Unable to unregister an AppArmor profile (%s, %s)", profileName, err.Error())
				return false
			}

			if !strings.Contains(string(content), "KubeArmor") {
				ae.Logger.Printf("Unabale to unregister an AppArmor profile (%s) (out-of-control)", profileName)
				return false
			}
		}

		if referenceCount, ok := ae.AppArmorProfiles[profileName]; ok {
			if referenceCount > 1 {
				ae.AppArmorProfiles[profileName]--
				ae.Logger.Printf("Unregistered an AppArmor profile (%s, refCount: %d)", profileName, ae.AppArmorProfiles[profileName])
			} else {
				delete(ae.AppArmorProfiles, profileName)
				ae.Logger.Printf("Unregistered an AppArmor profile (%s)", profileName)
			}
		} else {
			return false
		}
	} else {
		return ae.RegisterAppArmorProfile(profileName, false)
	}

	return true
}

// ====================================== //
// == AppArmor Host Profile Management == //
// ====================================== //

// CreateAppArmorHostProfile Function
func (ae *AppArmorEnforcer) CreateAppArmorHostProfile() error {
	apparmorHostDefault := "## == Managed by KubeArmor == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile kubearmor.host /** flags=(attach_disconnected,mediate_deleted) {\n" +
		"  ## == PRE START == ##\n" +
		"  #include <abstractions/base>\n" +
		"  mount,\n" +
		"  umount,\n" +
		"  ptrace,\n" +
		"  signal,\n" +
		"\n" +
		"  file,\n" +
		"  network,\n" +
		"  capability,\n" +
		"\n" +
		"  /usr/bin/runc Ux,\n" + // docker
		"  /usr/bin/docker-runc Ux, \n" + // docker
		"  /usr/sbin/runc Ux,\n" + // containerd
		"  /snap/microk8s/2262/bin/runc Ux,\n" + // microk8s
		"  /snap/microk8s/2264/bin/runc Ux,\n" + // microk8s
		"  ## == PRE END == ##\n" +
		"\n" +
		"  ## == POLICY START == ##\n" +
		"  ## == POLICY END == ##\n" +
		"}\n"

	newfile, err := os.Create(filepath.Clean("/etc/apparmor.d/kubearmor.host"))
	if err != nil {
		ae.Logger.Err(err.Error())
		return err
	}
	defer func() {
		if err := newfile.Close(); err != nil {
			ae.Logger.Err(err.Error())
		}
	}()

	if _, err := newfile.WriteString(apparmorHostDefault); err != nil {
		ae.Logger.Err(err.Error())
		return err
	}

	if err := newfile.Sync(); err != nil {
		ae.Logger.Err(err.Error())
		return err
	}

	ae.HostProfile = apparmorHostDefault

	return nil
}

// RemoveAppArmorHostProfile Function
func (ae *AppArmorEnforcer) RemoveAppArmorHostProfile() error {
	if _, err := os.Stat("/etc/apparmor.d/kubearmor.host"); err != nil {
		return nil
	}

	if err := os.Remove("/etc/apparmor.d/kubearmor.host"); err != nil {
		ae.Logger.Errf("Failed to remove the AppArmor host profile in %s (%s)", ae.HostName, err.Error())
		return err
	}

	return nil
}

// RegisterAppArmorHostProfile Function
func (ae *AppArmorEnforcer) RegisterAppArmorHostProfile() bool {
	if err := ae.CreateAppArmorHostProfile(); err != nil {
		ae.Logger.Errf("Failed to create the AppArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "-C", "/etc/apparmor.d/kubearmor.host"}); err == nil {
		ae.Logger.Printf("Registered an AppArmor host profile in %s", ae.HostName)
	} else {
		ae.Logger.Printf("Failed to registered an AppArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	return true
}

// UnregisterAppArmorHostProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorHostProfile() bool {
	if err := ae.RemoveAppArmorHostProfile(); err != nil {
		ae.Logger.Errf("Failed to remove the AppArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	return true
}

// ================================= //
// == Security Policy Enforcement == //
// ================================= //

// UpdateAppArmorProfile Function
func (ae *AppArmorEnforcer) UpdateAppArmorProfile(endPoint tp.EndPoint, appArmorProfile string, securityPolicies []tp.SecurityPolicy) {
	if policyCount, newProfile, ok := ae.GenerateAppArmorProfile(appArmorProfile, securityPolicies); ok {
		newfile, err := os.Create(filepath.Clean("/etc/apparmor.d/" + appArmorProfile))
		if err != nil {
			ae.Logger.Err(err.Error())
			return
		}
		defer func() {
			if err := newfile.Close(); err != nil {
				ae.Logger.Err(err.Error())
			}
		}()

		if _, err := newfile.WriteString(newProfile); err != nil {
			ae.Logger.Err(err.Error())
			return
		}

		if err := newfile.Sync(); err != nil {
			ae.Logger.Err(err.Error())
			return
		}

		if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + appArmorProfile}); err == nil {
			ae.Logger.Printf("Updated %d security rules to %s/%s/%s", policyCount, endPoint.NamespaceName, endPoint.EndPointName, appArmorProfile)
		} else {
			ae.Logger.Printf("Failed to update %d security rules to %s/%s/%s (%s)", policyCount, endPoint.NamespaceName, endPoint.EndPointName, appArmorProfile, err.Error())
		}
	}
}

// UpdateSecurityPolicies Function
func (ae *AppArmorEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	appArmorProfiles := []string{}

	for _, containerName := range endPoint.Containers {
		if kl.ContainsElement([]string{"docker-default", "unconfined", "cri-containerd.apparmor.d", ""}, endPoint.AppArmorProfiles[containerName]) {
			continue
		}

		if !kl.ContainsElement(appArmorProfiles, endPoint.AppArmorProfiles[containerName]) {
			appArmorProfiles = append(appArmorProfiles, endPoint.AppArmorProfiles[containerName])
		}
	}

	if endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
		for _, appArmorProfile := range appArmorProfiles {
			ae.UpdateAppArmorProfile(endPoint, appArmorProfile, endPoint.SecurityPolicies)
		}
	} else { // PolicyDisabled
		for _, appArmorProfile := range appArmorProfiles {
			ae.UpdateAppArmorProfile(endPoint, appArmorProfile, []tp.SecurityPolicy{})
		}
	}
}

// ====================================== //
// == Host Security Policy Enforcement == //
// ====================================== //

// UpdateAppArmorHostProfile Function
func (ae *AppArmorEnforcer) UpdateAppArmorHostProfile(secPolicies []tp.HostSecurityPolicy) {
	if policyCount, newProfile, ok := ae.GenerateAppArmorHostProfile(secPolicies); ok {
		newfile, err := os.Create(filepath.Clean("/etc/apparmor.d/kubearmor.host"))
		if err != nil {
			ae.Logger.Err(err.Error())
			return
		}
		defer func() {
			if err := newfile.Close(); err != nil {
				ae.Logger.Err(err.Error())
			}
		}()

		if _, err := newfile.WriteString(newProfile); err != nil {
			ae.Logger.Err(err.Error())
			return
		}

		if err := newfile.Sync(); err != nil {
			ae.Logger.Err(err.Error())
			return
		}

		if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/kubearmor.host"}); err == nil {
			ae.Logger.Printf("Updated %d host security rules to the AppArmor host profile in %s", policyCount, ae.HostName)
		} else {
			ae.Logger.Printf("Failed to update %d host security rules to the AppArmor host profile in %s (%s)", policyCount, ae.HostName, err.Error())
		}
	}
}

// UpdateHostSecurityPolicies Function
func (ae *AppArmorEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	if ae.EnableHostPolicy {
		ae.UpdateAppArmorHostProfile(secPolicies)
	} else {
		ae.UpdateAppArmorHostProfile([]tp.HostSecurityPolicy{})
	}
}
