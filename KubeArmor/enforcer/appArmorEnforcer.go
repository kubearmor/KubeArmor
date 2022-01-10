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
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
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

	// logs
	Logger *fd.Feeder

	// default profile
	ApparmorDefault string

	// host profile
	HostProfile string

	// profiles for containers
	AppArmorProfiles     map[string]int
	AppArmorProfilesLock *sync.RWMutex
}

// NewAppArmorEnforcer Function
func NewAppArmorEnforcer(node tp.Node, logger *fd.Feeder) *AppArmorEnforcer {
	ae := &AppArmorEnforcer{}

	// host
	ae.HostName = node.NodeName

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
	ae.AppArmorProfilesLock = &sync.RWMutex{}

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

	if cfg.GlobalCfg.HostPolicy {
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

	if cfg.GlobalCfg.HostPolicy {
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

	fname := filepath.Clean("/etc/apparmor.d/" + profileName)

	if _, err := os.Stat(fname); err == nil {
		content, err := ioutil.ReadFile(fname)
		if err != nil {
			ae.Logger.Errf("Unable to register an AppArmor profile (%s, %s)",
				profileName, err.Error())
			return false
		}

		if !strings.Contains(string(content), "KubeArmor") {
			ae.Logger.Errf("Unable to register an AppArmor profile (%s) (out-of-control)", profileName)
			return false
		}
	}

	newProfile := strings.Replace(ae.ApparmorDefault, "apparmor-default", profileName, -1)

	newFile, err := os.Create(fname)
	if err != nil {
		ae.Logger.Errf("Failed to create a profile (%s, %s)", fname, err.Error())
		return false
	}

	if _, err := newFile.WriteString(newProfile); err != nil {
		ae.Logger.Errf("Failed to initialize the profile (%s, %s)",
			fname, err.Error())

		if err := newFile.Close(); err != nil {
			ae.Logger.Errf("Failed to close the profile (%s, %s)", fname, err.Error())
		}

		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", fname}); err == nil {
		if _, ok := ae.AppArmorProfiles[profileName]; !ok {
			ae.AppArmorProfiles[profileName] = 1
			ae.Logger.Printf("Registered an AppArmor profile (%s)", profileName)
		}
	} else {
		ae.Logger.Errf("Failed to register an AppArmor profile (%s, %s)",
			profileName, err.Error())

		if err := newFile.Close(); err != nil {
			ae.Logger.Errf("Failed to close the profile (%s, %s)", fname, err.Error())
		}

		return false
	}

	if err := newFile.Close(); err != nil {
		ae.Logger.Errf("Failed to close the profile (%s, %s)", fname, err.Error())
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

	fname := filepath.Clean("/etc/apparmor.d/" + profileName)

	if _, err := os.Stat(fname); err == nil {
		content, err := ioutil.ReadFile(fname)
		if err != nil {
			ae.Logger.Errf("Unable to unregister an AppArmor profile (%s, %s)",
				profileName, err.Error())
			return false
		}

		if !strings.Contains(string(content), "KubeArmor") {
			ae.Logger.Errf("Unabale to unregister an AppArmor profile (%s) (out-of-control)", profileName)
			return false
		}
	}

	newProfile := strings.Replace(ae.ApparmorDefault, "apparmor-default", profileName, -1)

	newFile, err := os.Create(fname)
	if err != nil {
		ae.Logger.Errf("Failed to open a profile (%s, %s)", fname, err.Error())
		return false
	}

	if _, err := newFile.WriteString(newProfile); err != nil {
		ae.Logger.Errf("Failed to reset the profile (%s, %s)", fname, err.Error())

		if err := newFile.Close(); err != nil {
			ae.Logger.Errf("Failed to close the profile (%s, %s)", fname, err.Error())
		}

		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", fname}); err != nil {
		ae.Logger.Errf("Failed to unregister an AppArmor profile (%s, %s)",
			profileName, err.Error())

		if err := newFile.Close(); err != nil {
			ae.Logger.Errf("Failed to close the profile (%s, %s)", fname, err.Error())
		}

		return false
	}

	delete(ae.AppArmorProfiles, profileName)

	ae.Logger.Printf("Unregistered an AppArmor profile (%s)", profileName)

	if err := newFile.Close(); err != nil {
		ae.Logger.Errf("Failed to close the profile (%s, %s)", fname, err.Error())
	}

	return true
}

// ====================================== //
// == AppArmor Host Profile Management == //
// ====================================== //

// AppArmorEnforcer constants
const appArmorHostFile = "/etc/apparmor.d/kubearmor.host"

func clearKubeArmorHostFile(fileName string) {
	ae := &AppArmorEnforcer{}

	/* Remove contents of AppArmor profile once the policy is applied
	 * This will prevent reboot issues related to ungraceful shutdown of kubearmor
	 */
	if err := os.Truncate(fileName, 0); err != nil {
		ae.Logger.Err(err.Error())
	}
}

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

	newfile, err := os.Create(filepath.Clean(appArmorHostFile))
	if err != nil {
		ae.Logger.Errf("Failed to create the KubeArmor host profile (%s)", err.Error())
		return err
	}

	if _, err := newfile.WriteString(apparmorHostDefault); err != nil {
		ae.Logger.Errf("Failed to update the KubeArmor host profile (%s)", err.Error())

		if err := newfile.Close(); err != nil {
			ae.Logger.Errf("Failed to close the KubeArmor host profile (%s)", err.Error())
		}

		return err
	}

	ae.HostProfile = apparmorHostDefault

	if err := newfile.Close(); err != nil {
		ae.Logger.Errf("Failed to close the KubeArmor host profile (%s)", err.Error())
	}

	return nil
}

// RemoveAppArmorHostProfile Function
func (ae *AppArmorEnforcer) RemoveAppArmorHostProfile() error {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return nil
	}

	if _, err := os.Stat(appArmorHostFile); err != nil {
		ae.Logger.Errf("Failed to find the KubeArmor host profile in %s (%s)", ae.HostName, err.Error())
		return nil
	}

	if err := os.Remove(appArmorHostFile); err != nil {
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

	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

	if err := ae.CreateAppArmorHostProfile(); err != nil {
		ae.Logger.Errf("Failed to create the KubeArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "-C", appArmorHostFile}); err == nil {
		ae.Logger.Printf("Registered the KubeArmor host profile in %s", ae.HostName)
	} else {
		ae.Logger.Errf("Failed to registered the KubeArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	clearKubeArmorHostFile(appArmorHostFile)

	return true
}

// UnregisterAppArmorHostProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorHostProfile() bool {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return true
	}

	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

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

		if _, err := newfile.WriteString(newProfile); err != nil {
			ae.Logger.Err(err.Error())

			if err := newfile.Close(); err != nil {
				ae.Logger.Err(err.Error())
			}

			return
		}

		if err := newfile.Sync(); err != nil {
			ae.Logger.Err(err.Error())

			if err := newfile.Close(); err != nil {
				ae.Logger.Err(err.Error())
			}

			return
		}

		if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + appArmorProfile}); err == nil {
			ae.Logger.Printf("Updated %d security rule(s) to %s/%s/%s", policyCount, endPoint.NamespaceName, endPoint.EndPointName, appArmorProfile)
		} else {
			ae.Logger.Printf("Failed to update %d security rule(s) to %s/%s/%s (%s)", policyCount, endPoint.NamespaceName, endPoint.EndPointName, appArmorProfile, err.Error())
		}

		if err := newfile.Close(); err != nil {
			ae.Logger.Err(err.Error())
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
		newfile, err := os.Create(filepath.Clean(appArmorHostFile))
		if err != nil {
			ae.Logger.Err(err.Error())
			return
		}

		if _, err := newfile.WriteString(newProfile); err != nil {
			ae.Logger.Err(err.Error())

			if err := newfile.Close(); err != nil {
				ae.Logger.Err(err.Error())
			}

			return
		}

		if err := newfile.Sync(); err != nil {
			ae.Logger.Err(err.Error())

			if err := newfile.Close(); err != nil {
				ae.Logger.Err(err.Error())
			}

			return
		}

		if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", appArmorHostFile}); err == nil {
			ae.Logger.Printf("Updated %d host security rules to the KubeArmor host profile in %s", policyCount, ae.HostName)
		} else {
			ae.Logger.Errf("Failed to update %d host security rule(s) to the KubeArmor host profile in %s (%s)", policyCount, ae.HostName, err.Error())
		}

		if err := newfile.Close(); err != nil {
			ae.Logger.Err(err.Error())
		}

		clearKubeArmorHostFile(appArmorHostFile)
	}
}

// UpdateHostSecurityPolicies Function
func (ae *AppArmorEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return
	}

	if cfg.GlobalCfg.HostPolicy {
		ae.UpdateAppArmorHostProfile(secPolicies)
	} else {
		ae.UpdateAppArmorHostProfile([]tp.HostSecurityPolicy{})
	}
}
