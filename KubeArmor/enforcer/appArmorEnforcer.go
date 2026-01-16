// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

// Package enforcer is responsible for setting up and handling policy updates for supported enforcers including AppArmor, SELinux and BPFLSM
package enforcer

import (
	"os"
	"path/filepath"
	"regexp"
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
	// logs
	Logger *fd.Feeder

	// default profile
	ApparmorDefault string
	// default privileged profile
	ApparmorDefaultPrivileged string

	// host profile
	HostProfile string

	// profiles for containers
	AppArmorProfiles     map[string][]string
	AppArmorProfilesLock *sync.RWMutex

	// to keep track of privileged profiles for clean deletion
	AppArmorPrivilegedProfiles     map[string]struct{}
	AppArmorPrivilegedProfilesLock *sync.RWMutex

	// Regex used to get profile Names
	rgx *regexp.Regexp
}

// NewAppArmorEnforcer Function
func NewAppArmorEnforcer(node tp.Node, logger *fd.Feeder) *AppArmorEnforcer {
	ae := &AppArmorEnforcer{}

	// logs
	ae.Logger = logger

	// default profile
	ae.ApparmorDefault = `## == Managed by KubeArmor == ##
#include <tunables/global>

profile apparmor-default flags=(attach_disconnected,mediate_deleted) {
## == PRE START == ##
` + AppArmorDefaultPreStart +
		`
## == PRE END == ##

## == POLICY START == ##
## == POLICY END == ##

## == POST START == ##
` + AppArmorDefaultPostStart +
		`
## == POST END == ##
}
`

	ae.ApparmorDefaultPrivileged = `## == Managed by KubeArmor == ##
#include <tunables/global>

profile apparmor-default flags=(attach_disconnected,mediate_deleted) {
## == PRE START == ##
` + AppArmorPrivilegedPreStart +
		`
## == PRE END == ##

## == POLICY START == ##
## == POLICY END == ##

## == POST START == ##
` + AppArmorPrivilegedPostStart +
		`
## == POST END == ##
}
`
	// host profile
	ae.HostProfile = ""

	// profile regex

	ae.rgx = regexp.MustCompile("profile kubearmor-.* {")

	// profiles
	ae.AppArmorProfiles = map[string][]string{}
	ae.AppArmorProfilesLock = &sync.RWMutex{}

	ae.AppArmorPrivilegedProfiles = map[string]struct{}{}
	ae.AppArmorPrivilegedProfilesLock = new(sync.RWMutex)

	files, err := os.ReadDir("/etc/apparmor.d")
	if err != nil {
		ae.Logger.Errf("Failed to read /etc/apparmor.d (%s)", err.Error())
		return nil
	}

	existingProfiles := []string{}

	if pids, err := os.ReadDir(filepath.Clean(cfg.GlobalCfg.ProcFsMount)); err == nil {
		for _, f := range pids {
			if f.IsDir() {
				if _, err := strconv.Atoi(f.Name()); err == nil {
					if content, err := os.ReadFile(filepath.Clean(cfg.GlobalCfg.ProcFsMount + "/" + f.Name() + "/attr/current")); err == nil {
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
		if !file.Type().IsRegular() {
			ae.Logger.Printf("skipping /etc/apparmor.d/%s since not a regular file", file.Name())
			continue
		}

		fileName := file.Name()

		data, err := os.ReadFile(filepath.Clean("/etc/apparmor.d/" + fileName))
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
				ae.Logger.Warnf("Unable to detach /etc/apparmor.d/%s (%s)", fileName, err.Error())
				continue // still need to check other profiles
			}

			if err := os.Remove(filepath.Clean("/etc/apparmor.d/" + fileName)); err != nil {
				ae.Logger.Warnf("Unable to remove /etc/apparmor.d/%s (%s)", fileName, err.Error())
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
		_, privileged := ae.AppArmorPrivilegedProfiles[profile]
		ae.UnregisterAppArmorProfile("", profile, privileged)
	}

	if cfg.GlobalCfg.HostPolicy {
		ae.UnregisterAppArmorHostProfile()
	}

	ae = nil

	return nil
}

// ================================= //
// == AppArmor Profile Management == //
// ================================= //

// RegisterAppArmorProfile Function
func (ae *AppArmorEnforcer) RegisterAppArmorProfile(podName, profileName string, privileged bool) bool {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return true
	}

	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

	// this path is expected to have a single component "apparmor-profile"
	// and this is to ensure that the filename has no path separators or parent directory references
	if strings.Contains(profileName, "/") || strings.Contains(profileName, "\\") || strings.Contains(profileName, "..") {
		ae.Logger.Warnf("Invalid appArmor profile name (%s)", profileName)
		return false
	}

	if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + profileName)); err == nil {
		if content, err := os.ReadFile(filepath.Clean("/etc/apparmor.d/" + profileName)); err != nil {
			ae.Logger.Warnf("Unable to register the AppArmor profile (%s, %s))", profileName, err.Error())
			return false
		} else if !strings.Contains(string(content), "KubeArmor") {
			ae.Logger.Warnf("Unable to register the AppArmor profile (%s) (out-of-control)", profileName)
			return false
		}
	}
	if _, ok := ae.AppArmorProfiles[profileName]; ok {
		if !kl.ContainsElement(ae.AppArmorProfiles[profileName], podName) {
			ae.AppArmorProfiles[profileName] = append(ae.AppArmorProfiles[profileName], podName)
			ae.Logger.Printf("Added %s into the pod list of the AppArmor profile (%s, %d)", podName, profileName, len(ae.AppArmorProfiles[profileName]))
		}
		return true
	}

	// generate a profile with basic allows if a privileged container
	var newProfile string
	if privileged {
		newProfile = strings.ReplaceAll(ae.ApparmorDefaultPrivileged, "apparmor-default", profileName)
		ae.AppArmorPrivilegedProfiles[profileName] = struct{}{}
		ae.Logger.Printf("Added an AppArmor profile for a privileged container (%s, %s)", podName, profileName)
	} else {
		newProfile = strings.ReplaceAll(ae.ApparmorDefault, "apparmor-default", profileName)
	}

	newFile, err := os.Create(filepath.Clean("/etc/apparmor.d/" + profileName))
	if err != nil {
		ae.Logger.Warnf("Unable to create the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	if _, err := newFile.WriteString(newProfile); err != nil {
		ae.Logger.Warnf("Unable to initialize the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	if err := newFile.Close(); err != nil {
		ae.Logger.Warnf("Unable to close the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + profileName}); err != nil {
		ae.Logger.Warnf("Unable to register the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	ae.AppArmorProfiles[profileName] = []string{podName}

	ae.Logger.Printf("Registered the AppArmor profile (%s)", profileName)

	return true
}

// UnregisterAppArmorProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorProfile(podName, profileName string, privileged bool) bool {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return true
	}

	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

	if podName != "" {
		if _, ok := ae.AppArmorProfiles[profileName]; ok {
			for idx, registeredPodName := range ae.AppArmorProfiles[profileName] {
				if registeredPodName == podName {
					ae.AppArmorProfiles[profileName] = append(ae.AppArmorProfiles[profileName][:idx], ae.AppArmorProfiles[profileName][idx+1:]...)
					break
				}
			}

			ae.Logger.Printf("Removed %s from the pod list of the AppArmor profile (%s, %d)", podName, profileName, len(ae.AppArmorProfiles[profileName]))
			return true
		}
		ae.Logger.Warnf("Unable to find %s from the AppArmor profiles", profileName)
		return false
	}

	// this path is expected to have a single component "apparmor-profile"
	// and this is to ensure that the filename has no path separators or parent directory references
	if strings.Contains(profileName, "/") || strings.Contains(profileName, "\\") || strings.Contains(profileName, "..") {
		ae.Logger.Warnf("Invalid appArmor profile name (%s)", profileName)
		return false
	}

	if _, err := os.Stat(filepath.Clean("/etc/apparmor.d/" + profileName)); err != nil {
		ae.Logger.Warnf("Unable to find the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	if content, err := os.ReadFile(filepath.Clean("/etc/apparmor.d/" + profileName)); err != nil {
		ae.Logger.Warnf("Unable to read the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	} else if !strings.Contains(string(content), "KubeArmor") {
		ae.Logger.Warnf("Unable to unregister the AppArmor profile (%s) (out-of-control)", profileName)
		return false
	}

	var newProfile string
	if privileged {
		newProfile = strings.ReplaceAll(ae.ApparmorDefaultPrivileged, "apparmor-default", profileName)
	} else {
		newProfile = strings.ReplaceAll(ae.ApparmorDefault, "apparmor-default", profileName)
	}

	newFile, err := os.Create(filepath.Clean("/etc/apparmor.d/" + profileName))
	if err != nil {
		ae.Logger.Warnf("Unable to open the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	if _, err := newFile.WriteString(newProfile); err != nil {
		ae.Logger.Warnf("Unable to reset the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	if err := newFile.Close(); err != nil {
		ae.Logger.Warnf("Unable to close the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + profileName}); err != nil {
		ae.Logger.Warnf("Unable to unregister the AppArmor profile (%s, %s)", profileName, err.Error())
		return false
	}

	delete(ae.AppArmorProfiles, profileName)

	ae.Logger.Printf("Unregistered the AppArmor profile (%s)", profileName)

	return true
}

// ====================================== //
// == AppArmor Host Profile Management == //
// ====================================== //

// AppArmorEnforcer constants
const appArmorHostFile = "/etc/apparmor.d/kubearmor.host"

// ClearKubeArmorHostFile Function
func (ae *AppArmorEnforcer) ClearKubeArmorHostFile(fileName string) {
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

	apparmorHostDefault := `## == Managed by KubeArmor == ##
#include <tunables/global>

profile kubearmor.host /{usr/,}bin/*sh flags=(attach_disconnected,mediate_deleted) {
## == PRE START == ##
#include <abstractions/base>
mount,
umount,
signal,
unix,
ptrace,
dbus,

file,
network,
capability,
## == PRE END == ##

## == POLICY START == ##
## == POLICY END == ##
}
`
	newfile, err := os.Create(filepath.Clean(appArmorHostFile))
	if err != nil {
		ae.Logger.Warnf("Unable to open the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return err
	}

	if _, err := newfile.WriteString(apparmorHostDefault); err != nil {
		ae.Logger.Warnf("Unable to update the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return err
	}

	if err := newfile.Close(); err != nil {
		ae.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return err
	}

	ae.HostProfile = apparmorHostDefault

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
		ae.Logger.Warnf("Unable to create the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "-C", appArmorHostFile}); err != nil {
		ae.Logger.Warnf("Unable to register the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	ae.Logger.Printf("Registered the KubeArmor host profile in %s", cfg.GlobalCfg.Host)

	ae.ClearKubeArmorHostFile(appArmorHostFile)

	return true
}

// UnregisterAppArmorHostProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorHostProfile() bool {
	// skip if AppArmorEnforcer is not active
	if ae == nil {
		return true
	}

	ae.Logger.Printf("Unregistering the KubeArmor host profile from %s", cfg.GlobalCfg.Host)

	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

	if err := kl.RunCommandAndWaitWithErr("aa-remove-unknown", []string{}); err != nil {
		ae.Logger.Warnf("Unable to cleanup the KubeArmor host profile in %s", cfg.GlobalCfg.Host)

		if err := ae.CreateAppArmorHostProfile(); err != nil {
			ae.Logger.Warnf("Unable to reset the KubeArmor host profile in %s", cfg.GlobalCfg.Host)

			if err := os.Remove(appArmorHostFile); err != nil {
				ae.Logger.Warnf("Unable to remove the KubeArmor host profile from %s (%s)", cfg.GlobalCfg.Host, err.Error())
			}

			return false
		}

		if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "-C", appArmorHostFile}); err != nil {
			ae.Logger.Warnf("Unable to reset the KubeArmor host profile in %s", cfg.GlobalCfg.Host)

			if err := os.Remove(appArmorHostFile); err != nil {
				ae.Logger.Warnf("Unable to remove the KubeArmor host profile from %s (%s)", cfg.GlobalCfg.Host, err.Error())
			}

		}

		if err := os.Remove(appArmorHostFile); err != nil {
			ae.Logger.Warnf("Unable to remove the KubeArmor host profile from %s (%s)", cfg.GlobalCfg.Host, err.Error())
			return false
		}
	}

	ae.Logger.Printf("Unregistered the KubeArmor host profile from %s", cfg.GlobalCfg.Host)

	return true
}

// ================================= //
// == Security Policy Enforcement == //
// ================================= //

// UpdateAppArmorProfile Function
func (ae *AppArmorEnforcer) UpdateAppArmorProfile(endPoint tp.EndPoint, appArmorProfile string, securityPolicies []tp.SecurityPolicy) {

	/* For privileged profiles, we maintain a separate map so that privileged pods
	   are identified separately and their profiles are generated accordingly
	*/
	ae.AppArmorPrivilegedProfilesLock.Lock()
	_, privileged := ae.AppArmorPrivilegedProfiles[appArmorProfile]
	ae.AppArmorPrivilegedProfilesLock.Unlock()

	if policyCount, newProfile, ok := ae.GenerateAppArmorProfile(appArmorProfile, securityPolicies, endPoint.DefaultPosture, privileged); ok {
		// this path is expected to have a single componenet "apparmor-profile"
		// and this is to ensure that the filename has no path separators or parent directory references
		if strings.Contains(appArmorProfile, "/") || strings.Contains(appArmorProfile, "\\") || strings.Contains(appArmorProfile, "..") {
			ae.Logger.Warnf("Invalid AppArmor profile name (%s)", appArmorProfile)
			return
		}
		newfile, err := os.Create(filepath.Clean("/etc/apparmor.d/" + appArmorProfile))
		if err != nil {
			ae.Logger.Warnf("Unable to open an AppArmor profile (%s, %s)", appArmorProfile, err.Error())
			return
		}

		if _, err := newfile.WriteString(newProfile); err != nil {
			ae.Logger.Warnf("Unable to update the AppArmor profile (%s, %s)", appArmorProfile, err.Error())

			if err := newfile.Close(); err != nil {
				ae.Logger.Warnf("Unable to close the AppArmor profile (%s, %s)", appArmorProfile, err.Error())
			}

			return
		}

		if err := newfile.Sync(); err != nil {
			ae.Logger.Warnf("Unable to sync the AppArmor profile (%s, %s)", appArmorProfile, err.Error())

			if err := newfile.Close(); err != nil {
				ae.Logger.Warnf("Unable to close the AppArmor profile (%s, %s)", appArmorProfile, err.Error())
			}

			return
		}

		if err := newfile.Close(); err != nil {
			ae.Logger.Warnf("Unable to close the AppArmor profile (%s, %s)", appArmorProfile, err.Error())
			return
		}

		if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + appArmorProfile}); err != nil {
			ae.Logger.Warnf("Unable to update %d security rule(s) to %s/%s/%s (%s)", policyCount, endPoint.NamespaceName, endPoint.EndPointName, appArmorProfile, err.Error())
			return
		}

		if cfg.GlobalCfg.K8sEnv {
			if err := kl.RunCommandAndWaitWithErr("aa-disable", []string{"/etc/apparmor.d/" + appArmorProfile}); err != nil {
				ae.Logger.Warnf("Unable to disable for a weird issue %d security rule(s) to %s/%s/%s (%s)", policyCount, endPoint.NamespaceName, endPoint.EndPointName, appArmorProfile, err.Error())
				return
			}
			if err := kl.RunCommandAndWaitWithErr("aa-enforce", []string{"/etc/apparmor.d/" + appArmorProfile}); err != nil {
				ae.Logger.Warnf("Unable to enforce back for a weird issue %d security rule(s) to %s/%s/%s (%s)", policyCount, endPoint.NamespaceName, endPoint.EndPointName, appArmorProfile, err.Error())
				return
			}
		}

		ae.Logger.Printf("Updated %d security rule(s) to %s/%s/%s", policyCount, endPoint.NamespaceName, endPoint.EndPointName, appArmorProfile)
	} else if newProfile != "" {
		ae.Logger.Errf("Error Generating %s AppArmor profile: %s", appArmorProfile, newProfile)
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
		if kl.ContainsElement([]string{"docker-default", "unconfined", "cri-containerd.apparmor.d", "crio-default", ""}, appArmorProfile) {
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
	globalDefaultPosture := tp.DefaultPosture{
		FileAction:         cfg.GlobalCfg.HostDefaultFilePosture,
		NetworkAction:      cfg.GlobalCfg.HostDefaultNetworkPosture,
		CapabilitiesAction: cfg.GlobalCfg.HostDefaultCapabilitiesPosture,
	}

	var hostPolicies []tp.SecurityPolicy

	// Typecast HostSecurityPolicy spec to normal SecurityPolicies
	for _, secPolicy := range secPolicies {
		var hostPolicy tp.SecurityPolicy
		if err := kl.Clone(secPolicy.Spec.Process, &hostPolicy.Spec.Process); err != nil {
			ae.Logger.Warnf("Error cloning host policy spec process to sec policy construct")
		}
		if err := kl.Clone(secPolicy.Spec.File, &hostPolicy.Spec.File); err != nil {
			ae.Logger.Warnf("Error cloning host policy spec file to sec policy construct")
		}
		if err := kl.Clone(secPolicy.Spec.Network, &hostPolicy.Spec.Network); err != nil {
			ae.Logger.Warnf("Error cloning host policy spec network to sec policy construct")
		}
		if err := kl.Clone(secPolicy.Spec.Capabilities, &hostPolicy.Spec.Capabilities); err != nil {
			ae.Logger.Warnf("Error cloning host policy spec capabilities to sec policy construct")
		}
		if err := kl.Clone(secPolicy.Spec.Syscalls, &hostPolicy.Spec.Syscalls); err != nil {
			ae.Logger.Warnf("Error cloning host policy spec syscall to sec policy construct")
		}
		hostPolicies = append(hostPolicies, hostPolicy)
	}

	if policyCount, newProfile, ok := ae.GenerateAppArmorProfile("kubearmor.host /{usr/,}bin/*sh", hostPolicies, globalDefaultPosture, true); ok {
		newfile, err := os.Create(filepath.Clean(appArmorHostFile))
		if err != nil {
			ae.Logger.Warnf("Unable to open the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			return
		}

		if _, err := newfile.WriteString(newProfile); err != nil {
			ae.Logger.Warnf("Unable to update the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())

			if err := newfile.Close(); err != nil {
				ae.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			}

			return
		}

		if err := newfile.Sync(); err != nil {
			ae.Logger.Warnf("Unable to sync the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())

			if err := newfile.Close(); err != nil {
				ae.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			}

			return
		}

		if err := newfile.Close(); err != nil {
			ae.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			return
		}

		if err := kl.RunCommandAndWaitWithErr("apparmor_parser", []string{"-r", "-W", appArmorHostFile}); err != nil {
			ae.Logger.Warnf("Unable to update %d host security rule(s) to the KubeArmor host profile in %s (%s)", policyCount, cfg.GlobalCfg.Host, err.Error())
			return
		}

		ae.Logger.Printf("Updated %d host security rules to the KubeArmor host profile in %s", policyCount, cfg.GlobalCfg.Host)

		ae.ClearKubeArmorHostFile(appArmorHostFile)
	} else if newProfile != "" {
		ae.Logger.Errf("Error Generating %s AppArmor profile: %s", appArmorHostFile, newProfile)
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
