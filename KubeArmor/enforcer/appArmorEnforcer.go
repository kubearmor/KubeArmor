// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

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
	// host
	HostName string

	// options
	EnableKubeArmorPolicy     bool
	EnableKubeArmorHostPolicy bool

	// logs
	Logger *fd.Feeder

	// default profile
	ApparmorDefault string

	// host profile
	HostProfile string

	// profiles for containers
	AppArmorProfiles     map[string]int
	AppArmorProfilesLock *sync.Mutex
}

// NewAppArmorEnforcer Function
func NewAppArmorEnforcer(node tp.Node, logger *fd.Feeder) *AppArmorEnforcer {
	ae := &AppArmorEnforcer{}

	// host
	ae.HostName = node.NodeName

	// options
	ae.EnableKubeArmorPolicy = node.EnableKubeArmorPolicy
	ae.EnableKubeArmorHostPolicy = node.EnableKubeArmorHostPolicy

	// logs
	ae.Logger = logger

	// default profile
	ae.ApparmorDefault = "## == Managed by KubeArmor == ##\n" +
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
		"  /lib/x86_64-linux-gnu/{*,**} rm,\n" +
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

	if ae.EnableKubeArmorHostPolicy {
		if ok := ae.RegisterAppArmorHostProfile(); !ok {
			return nil
		}
	}

	return ae
}

// DestroyAppArmorEnforcer Function
func (ae *AppArmorEnforcer) DestroyAppArmorEnforcer() error {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return nil
	}

	for profile := range ae.AppArmorProfiles {
		ae.UnregisterAppArmorProfile(profile)
	}

	if ae.EnableKubeArmorHostPolicy {
		ae.UnregisterAppArmorHostProfile()
	}

	return nil
}

// ================================= //
// == AppArmor Profile Management == //
// ================================= //

// RegisterAppArmorProfile Function
func (ae *AppArmorEnforcer) RegisterAppArmorProfile(profileName string) bool {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return true
	}

	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

	if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + profileName)); err == nil {
		content, err := ioutil.ReadFile(filepath.Clean("/etc/apparmor.d/" + profileName))
		if err != nil {
			ae.Logger.Errf("Unable to register an AppArmor profile (%s, %s)", profileName, err.Error())
			return false
		}

		if !strings.Contains(string(content), "KubeArmor") {
			ae.Logger.Errf("Unable to register an AppArmor profile (%s) (out-of-control)", profileName)
			return false
		}
	}

	newProfile := strings.Replace(ae.ApparmorDefault, "apparmor-default", profileName, -1)

	newFile, err := os.Create(filepath.Clean("/etc/apparmor.d/" + profileName))
	if err != nil {
		ae.Logger.Errf("Failed to create a profile (%s, %s)", "/etc/apparmor.d/"+profileName, err.Error())
		return false
	}
	defer func() {
		if err := newFile.Close(); err != nil {
			ae.Logger.Errf("Failed to close the profile (%s, %s)", "/etc/apparmor.d/"+profileName, err.Error())
		}
	}()

	if _, err := newFile.WriteString(newProfile); err != nil {
		ae.Logger.Errf("Failed to initialize the profile (%s, %s)", "/etc/apparmor.d/"+profileName, err.Error())
		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + profileName}); err == nil {
		if _, ok := ae.AppArmorProfiles[profileName]; !ok {
			ae.AppArmorProfiles[profileName] = 1
			ae.Logger.Printf("Registered an AppArmor profile (%s)", profileName)
		}
	} else {
		ae.Logger.Errf("Failed to register an AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	return true
}

// UnregisterAppArmorProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorProfile(profileName string) bool {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return true
	}

	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

	if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + profileName)); err == nil {
		content, err := ioutil.ReadFile(filepath.Clean("/etc/apparmor.d/" + profileName))
		if err != nil {
			ae.Logger.Errf("Unable to unregister an AppArmor profile (%s, %s)", profileName, err.Error())
			return false
		}

		if !strings.Contains(string(content), "KubeArmor") {
			ae.Logger.Errf("Unabale to unregister an AppArmor profile (%s) (out-of-control)", profileName)
			return false
		}
	}

	newProfile := strings.Replace(ae.ApparmorDefault, "apparmor-default", profileName, -1)

	newFile, err := os.Create(filepath.Clean("/etc/apparmor.d/" + profileName))
	if err != nil {
		ae.Logger.Errf("Failed to open a profile (%s, %s)", "/etc/apparmor.d/"+profileName, err.Error())
		return false
	}
	defer func() {
		if err := newFile.Close(); err != nil {
			ae.Logger.Errf("Failed to close the profile (%s, %s)", "/etc/apparmor.d/"+profileName, err.Error())
		}
	}()

	if _, err := newFile.WriteString(newProfile); err != nil {
		ae.Logger.Errf("Failed to reset the profile (%s, %s)", "/etc/apparmor.d/"+profileName, err.Error())
		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + profileName}); err != nil {
		ae.Logger.Errf("Failed to unregister an AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	delete(ae.AppArmorProfiles, profileName)

	ae.Logger.Printf("Unregistered an AppArmor profile (%s)", profileName)

	return true
}

// ====================================== //
// == AppArmor Host Profile Management == //
// ====================================== //

// CreateAppArmorHostProfile Function
func (ae *AppArmorEnforcer) CreateAppArmorHostProfile() error {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return nil
	}

	apparmorHostDefault := "## == Managed by KubeArmor == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile kubearmor.host /{usr/,}bin/*sh flags=(attach_disconnected,mediate_deleted) {\n" +
		"  ## == PRE START == ##\n" +
		"  #include <abstractions/base>\n" +
		"  mount,\n" +
		"  umount,\n" +
		"  signal,\n" +
		"  unix,\n" +
		"\n" +
		"  file,\n" +
		"  network,\n" +
		"  capability,\n" +
		"  ## == PRE END == ##\n" +
		"\n" +
		"  ## == POLICY START == ##\n" +
		"  ## == POLICY END == ##\n" +
		"}\n"

	newfile, err := os.Create(filepath.Clean("/etc/apparmor.d/kubearmor.host"))
	if err != nil {
		ae.Logger.Errf("Failed to create the KubeArmor host profile (%s)", err.Error())
		return err
	}
	defer func() {
		if err := newfile.Close(); err != nil {
			ae.Logger.Errf("Failed to close the KubeArmor host profile (%s)", err.Error())
		}
	}()

	if _, err := newfile.WriteString(apparmorHostDefault); err != nil {
		ae.Logger.Errf("Failed to update the KubeArmor host profile (%s)", err.Error())
		return err
	}

	ae.HostProfile = apparmorHostDefault

	return nil
}

// RemoveAppArmorHostProfile Function
func (ae *AppArmorEnforcer) RemoveAppArmorHostProfile() error {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return nil
	}

	if _, err := os.Stat("/etc/apparmor.d/kubearmor.host"); err != nil {
		ae.Logger.Errf("Failed to find the KubeArmor host profile in %s (%s)", ae.HostName, err.Error())
		return nil
	}

	if err := os.Remove("/etc/apparmor.d/kubearmor.host"); err != nil {
		ae.Logger.Errf("Failed to remove the KubeArmor host profile in %s (%s)", ae.HostName, err.Error())
		return err
	}

	return nil
}

// RegisterAppArmorHostProfile Function
func (ae *AppArmorEnforcer) RegisterAppArmorHostProfile() bool {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return true
	}

	if err := ae.CreateAppArmorHostProfile(); err != nil {
		ae.Logger.Errf("Failed to create the KubeArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "-C", "/etc/apparmor.d/kubearmor.host"}); err == nil {
		ae.Logger.Printf("Registered the KubeArmor host profile in %s", ae.HostName)
	} else {
		ae.Logger.Errf("Failed to registered the KubeArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	return true
}

// UnregisterAppArmorHostProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorHostProfile() bool {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return true
	}

	if err := ae.RemoveAppArmorHostProfile(); err != nil {
		ae.Logger.Errf("Failed to remove the KubeArmor host profile in %s (%s)", ae.HostName, err.Error())
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
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return
	}

	appArmorProfiles := []string{}

	for _, appArmorProfile := range endPoint.AppArmorProfiles {
		if kl.ContainsElement([]string{"docker-default", "unconfined", "cri-containerd.apparmor.d", ""}, appArmorProfile) {
			continue
		}

		if !kl.ContainsElement(appArmorProfiles, appArmorProfile) {
			appArmorProfiles = append(appArmorProfiles, appArmorProfile)
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
			ae.Logger.Printf("Updated %d host security rules to the KubeArmor host profile in %s", policyCount, ae.HostName)
		} else {
			ae.Logger.Errf("Failed to update %d host security rules to the KubeArmor host profile in %s (%s)", policyCount, ae.HostName, err.Error())
		}
	}
}

// UpdateHostSecurityPolicies Function
func (ae *AppArmorEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return
	}

	if ae.EnableKubeArmorHostPolicy {
		ae.UpdateAppArmorHostProfile(secPolicies)
	} else {
		ae.UpdateAppArmorHostProfile([]tp.HostSecurityPolicy{})
	}
}
