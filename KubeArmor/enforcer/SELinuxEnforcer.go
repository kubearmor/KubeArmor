// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ====================== //
// == SELinux Enforcer == //
// ====================== //

// SELinuxEnforcer Structure
type SELinuxEnforcer struct {
	// logs
	Logger *fd.Feeder

	// policy enforcer
	SELinuxTemplatePath string

	// host profile
	HostProfile string

	// profiles for containers
	SELinuxProfiles     map[string][]string
	SELinuxProfilesLock *sync.Mutex
}

// NewSELinuxEnforcer Function
func NewSELinuxEnforcer(node tp.Node, logger *fd.Feeder) *SELinuxEnforcer {
	se := &SELinuxEnforcer{}

	// logs
	se.Logger = logger

	homeDir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		se.Logger.Errf("Failed to get the current directory (%s)", err.Error())
		return nil
	}

	// to get SELinux modules and inject/remove new modules
	if _, err := os.Stat(filepath.Clean("/usr/sbin/semanage")); err != nil {
		se.Logger.Errf("Failed to find /usr/sbin/semanage (%s)", err.Error())
		return nil
	}

	// to change the labels of files and directories
	if _, err := os.Stat(filepath.Clean("/usr/bin/chcon")); err != nil {
		se.Logger.Errf("Failed to find /usr/bin/chcon (%s)", err.Error())
		return nil
	}

	// to recover the original labels of files and directories
	if _, err := os.Stat(filepath.Clean("/usr/sbin/restorecon")); err != nil {
		se.Logger.Errf("Failed to find /usr/sbin/restorecon (%s)", err.Error())
		return nil
	}

	// SELinux templates
	templatePath := homeDir + "/templates"
	if _, err := os.Stat(filepath.Clean(templatePath + "/install.sh")); err != nil {
		// go test
		templatePath = os.Getenv("PWD") + "/../templates"
		if _, err := os.Stat(filepath.Clean(templatePath + "/install.sh")); err != nil {
			se.Logger.Err("Failed to find templates/install.sh")
			return nil
		}
	}
	se.SELinuxTemplatePath = templatePath

	// check the SELinux profile directory
	if ok := strings.HasSuffix(cfg.GlobalCfg.SELinuxProfileDir, "/"); !ok {
		cfg.GlobalCfg.SELinuxProfileDir = cfg.GlobalCfg.SELinuxProfileDir + "/"
	}

	// remove old profiles if exists
	if err = os.RemoveAll(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir)); err != nil {
		se.Logger.Errf("Failed to remove existing SELinux profiles (%s)", err.Error())
		return nil
	}

	// create a profile directory if not exists
	if err := os.MkdirAll(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir), 0750); err != nil {
		se.Logger.Errf("Failed to create %s (%s)", cfg.GlobalCfg.SELinuxProfileDir, err.Error())
		return nil
	}

	// host profile
	se.HostProfile = "kubearmor.host"

	// profiles
	se.SELinuxProfiles = map[string][]string{}
	se.SELinuxProfilesLock = &sync.Mutex{}

	if cfg.GlobalCfg.HostPolicy {
		if ok := se.RegisterSELinuxHostProfile(); !ok {
			return nil
		}
	}

	return se
}

// DestroySELinuxEnforcer Function
func (se *SELinuxEnforcer) DestroySELinuxEnforcer() error {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return nil
	}

	for profileName := range se.SELinuxProfiles {
		se.UnregisterSELinuxProfile("", profileName)
	}

	if cfg.GlobalCfg.HostPolicy {
		se.UnregisterSELinuxHostProfile()
	}

	return nil
}

// ================================ //
// == SELinux Profile Management == //
// ================================ //

// RegisterSELinuxProfile Function
func (se *SELinuxEnforcer) RegisterSELinuxProfile(podName, profileName string) bool {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return true
	}

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	if _, err := os.Stat(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + profileName)); err == nil {
		if _, err := ioutil.ReadFile(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + profileName)); err != nil {
			se.Logger.Warnf("Unable to register the SELinux profile (%s, %s))", profileName, err.Error())
			return false
		}
	}

	if _, ok := se.SELinuxProfiles[profileName]; ok {
		if !kl.ContainsElement(se.SELinuxProfiles[profileName], podName) {
			se.SELinuxProfiles[profileName] = append(se.SELinuxProfiles[profileName], podName)
			se.Logger.Printf("Added %s into the pod list of the SELinux profile (%s, %d)", podName, profileName, len(se.SELinuxProfiles[profileName]))
		}
		return true
	}

	newFile, err := os.Create(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + profileName))
	if err != nil {
		se.Logger.Warnf("Unable to create the SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	if _, err := newFile.WriteString(""); err != nil {
		se.Logger.Warnf("Unable to update the SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	if err := newFile.Close(); err != nil {
		se.Logger.Warnf("Unable to close the SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	if ok := se.UpdateSELinuxLabels(cfg.GlobalCfg.SELinuxProfileDir + profileName); !ok {
		se.Logger.Warnf("Unable to register the SELinux profile (%s)", profileName)
		return false
	}

	se.SELinuxProfiles[profileName] = []string{podName}

	se.Logger.Printf("Registered the SELinux profile (%s)", profileName)

	return true
}

// UnregisterSELinuxProfile Function
func (se *SELinuxEnforcer) UnregisterSELinuxProfile(podName, profileName string) bool {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return true
	}

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	if podName != "" {
		if _, ok := se.SELinuxProfiles[profileName]; ok {
			for idx, registeredPodName := range se.SELinuxProfiles[profileName] {
				if registeredPodName == podName {
					se.SELinuxProfiles[profileName] = append(se.SELinuxProfiles[profileName][:idx], se.SELinuxProfiles[profileName][idx+1:]...)
					break
				}
			}

			if len(se.SELinuxProfiles[profileName]) > 0 {
				se.Logger.Printf("Removed %s from the pod list of the SELinux profile (%s, %d)", podName, profileName, len(se.SELinuxProfiles[profileName]))
				return true
			}
		} else {
			se.Logger.Warnf("Unable to find %s from the SELinux profiles", profileName)
			return false
		}
	}

	if _, err := os.Stat(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + profileName)); err != nil {
		se.Logger.Warnf("Unable to find the SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	newFile, err := os.Create(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + profileName))
	if err != nil {
		se.Logger.Warnf("Unable to open the SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	if _, err := newFile.WriteString(""); err != nil {
		se.Logger.Warnf("Unable to reset the SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	if err := newFile.Close(); err != nil {
		se.Logger.Warnf("Unable to close the SELinux profile (%s, %s)", profileName, err.Error())
		return false
	}

	if ok := se.UpdateSELinuxLabels(cfg.GlobalCfg.SELinuxProfileDir + profileName); !ok {
		se.Logger.Warnf("Unable to unregister the SELinux profile (%s)", profileName)
		return false
	}

	delete(se.SELinuxProfiles, profileName)

	se.Logger.Printf("Unregistered the SELinux profile (%s)", profileName)

	return true
}

// ===================================== //
// == SELinux Host Profile Management == //
// ===================================== //

// RegisterSELinuxHostProfile Function
func (se *SELinuxEnforcer) RegisterSELinuxHostProfile() bool {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return true
	}

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	newFile, err := os.Create(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile))
	if err != nil {
		se.Logger.Warnf("Unable to create the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if _, err := newFile.WriteString(""); err != nil {
		se.Logger.Warnf("Unable to update the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if err := newFile.Close(); err != nil {
		se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if ok := se.UpdateSELinuxLabels(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile); !ok {
		se.Logger.Warnf("Unable to register the KubeArmor host profile in %s", cfg.GlobalCfg.Host)
		return false
	}

	se.Logger.Printf("Registered the KubeArmor host profile in %s", cfg.GlobalCfg.Host)

	return true
}

// UnregisterSELinuxHostProfile Function
func (se *SELinuxEnforcer) UnregisterSELinuxHostProfile() bool {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return true
	}

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	newFile, err := os.Create(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile))
	if err != nil {
		se.Logger.Warnf("Unable to open the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if _, err := newFile.WriteString(""); err != nil {
		se.Logger.Warnf("Unable to update the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if err := newFile.Close(); err != nil {
		se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
		return false
	}

	if ok := se.UpdateSELinuxLabels(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile); !ok {
		se.Logger.Warnf("Unable to unregister the KubeArmor host profile in %s", cfg.GlobalCfg.Host)
		return false
	}

	se.Logger.Printf("Unregistered the KubeArmor host profile from %s", cfg.GlobalCfg.Host)

	return true
}

// ================================= //
// == Security Policy Enforcement == //
// ================================= //

// UpdateSELinuxProfile Function
func (se *SELinuxEnforcer) UpdateSELinuxProfile(endPoint tp.EndPoint, seLinuxProfile string, securityPolicies []tp.SecurityPolicy) {
	if policyCount, newProfile, sources, ok := se.GenerateSELinuxProfile(seLinuxProfile, securityPolicies); ok {
		if ok := se.InstallSELinuxModulesIfNeeded(sources); !ok {
			se.Logger.Warnf("Unable to install SELinux modules required by the SELinux profile (%s)", seLinuxProfile)
			return
		}

		newfile, err := os.Create(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + seLinuxProfile))
		if err != nil {
			se.Logger.Warnf("Unable to open the SELinux profile (%s, %s)", seLinuxProfile, err.Error())
			return
		}

		if _, err := newfile.WriteString(newProfile); err != nil {
			se.Logger.Warnf("Unable to update the SELinux profile (%s, %s)", seLinuxProfile, err.Error())

			if err := newfile.Close(); err != nil {
				se.Logger.Warnf("Unable to close the SELinux profile (%s, %s)", seLinuxProfile, err.Error())
			}

			return
		}

		if err := newfile.Sync(); err != nil {
			se.Logger.Warnf("Unable to sync the SELinux profile (%s, %s)", seLinuxProfile, err.Error())

			if err := newfile.Close(); err != nil {
				se.Logger.Warnf("Unable to close the SELinux profile (%s, %s)", seLinuxProfile, err.Error())
			}

			return
		}

		if err := newfile.Close(); err != nil {
			se.Logger.Warnf("Unable to close the SELinux profile (%s, %s)", seLinuxProfile, err.Error())
			return
		}

		if ok := se.UpdateSELinuxLabels(cfg.GlobalCfg.SELinuxProfileDir + seLinuxProfile); !ok {
			se.Logger.Warnf("Unable to update SELinux labels affected by the SELinux profile (%s)", seLinuxProfile)
			return
		}

		se.Logger.Printf("Updated %d security rule(s) to %s/%s/%s", policyCount, endPoint.NamespaceName, endPoint.EndPointName, seLinuxProfile)
	}
}

// UpdateSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return
	}

	selinuxProfiles := []string{}

	for _, seLinuxProfile := range endPoint.SELinuxProfiles {
		if !kl.ContainsElement(selinuxProfiles, seLinuxProfile) {
			selinuxProfiles = append(selinuxProfiles, seLinuxProfile)
		}
	}

	if endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
		for _, selinuxProfile := range selinuxProfiles {
			se.UpdateSELinuxProfile(endPoint, selinuxProfile, endPoint.SecurityPolicies)
		}
	} else { // PolicyDisabled
		for _, selinuxProfile := range selinuxProfiles {
			se.UpdateSELinuxProfile(endPoint, selinuxProfile, []tp.SecurityPolicy{})
		}
	}
}

// ====================================== //
// == Host Security Policy Enforcement == //
// ====================================== //

// UpdateSELinuxHostProfile Function
func (se *SELinuxEnforcer) UpdateSELinuxHostProfile(secPolicies []tp.HostSecurityPolicy) {
	if policyCount, newProfile, sources, ok := se.GenerateSELinuxHostProfile(secPolicies); ok {
		if ok := se.InstallSELinuxModulesIfNeeded(sources); !ok {
			se.Logger.Warnf("Unable to install SELinux modules required by the KubeArmor host profile in %s", cfg.GlobalCfg.Host)
			return
		}

		newFile, err := os.Create(filepath.Clean(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile))
		if err != nil {
			se.Logger.Warnf("Unable to open the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			return
		}

		if _, err := newFile.WriteString(newProfile); err != nil {
			se.Logger.Warnf("Unable to update the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())

			if err := newFile.Close(); err != nil {
				se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			}

			return
		}

		if err := newFile.Sync(); err != nil {
			se.Logger.Warnf("Unable to sync the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())

			if err := newFile.Close(); err != nil {
				se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			}

			return
		}

		if err := newFile.Close(); err != nil {
			se.Logger.Warnf("Unable to close the KubeArmor host profile in %s (%s)", cfg.GlobalCfg.Host, err.Error())
			return
		}

		if ok := se.UpdateSELinuxLabels(cfg.GlobalCfg.SELinuxProfileDir + se.HostProfile); !ok {
			se.Logger.Warnf("Unable to update SELinux labels affected by the KubeArmor host profile in %s", cfg.GlobalCfg.Host)
			return
		}

		se.Logger.Printf("Updated %d host security rule(s) to the KubeArmor host profile in %s", policyCount, cfg.GlobalCfg.Host)
	}
}

// UpdateHostSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if SELinuxEnforcer is not active
	if se == nil {
		return
	}

	if cfg.GlobalCfg.HostPolicy {
		se.UpdateSELinuxHostProfile(secPolicies)
	} else {
		se.UpdateSELinuxHostProfile([]tp.HostSecurityPolicy{})
	}
}

// ============================= //
// == SELinux Rule Management == //
// ============================= //

// ContainsElement Function
func (se *SELinuxEnforcer) ContainsElement(rules []tp.SELinuxRule, newRule tp.SELinuxRule) bool {
	for _, rule := range rules {
		if rule.SubjectPath == newRule.SubjectPath && rule.ObjectPath == newRule.ObjectPath {
			return true
		}
	}
	return false
}

// InstallSELinuxModulesIfNeeded Function
func (se *SELinuxEnforcer) InstallSELinuxModulesIfNeeded(sources []string) bool {
	modules := []string{}

	res, err := kl.GetCommandOutputWithErr("/usr/sbin/semanage", []string{"module", "-l"})
	if err != nil {
		se.Logger.Warnf("Unable to read the list of SELinux modules (%s)", err.Error())
		return false
	}

	for _, line := range strings.Split(res, "\n") {
		// fields: ModuleName Priority Language
		words := strings.Fields(line)

		if len(words) == 3 && strings.HasPrefix(words[0], "karmor") {
			modules = append(modules, words[0])
		}
	}

	for _, source := range sources {
		if kl.ContainsElement(modules, source) {
			continue
		}

		se.Logger.Printf("Installing a SELinux module (%s)", source)

		if err := kl.RunCommandAndWaitWithErr(se.SELinuxTemplatePath+"/install.sh", []string{source}); err == nil {
			se.Logger.Printf("Installed the SELinux module (%s)", source)
		} else {
			se.Logger.Warnf("Unable to install a SELinux module (%s)", source)
			return false
		}
	}

	return true
}

// RestoreSELinuxLabels Function
func (se *SELinuxEnforcer) RestoreSELinuxLabels(profilePath string) bool {
	if _, err := os.Stat(filepath.Clean(profilePath + ".old")); err != nil {
		return true
	}

	profile, err := ioutil.ReadFile(filepath.Clean(profilePath + ".old"))
	if err != nil {
		se.Logger.Warnf("Unable to read %s", profilePath+".old")
		return false
	}

	res := true

	for _, line := range strings.Split(string(profile), "\n") {
		// fields: SubjectLabel SubjectPath ObjectLabel ObjectPath Permissive Directory Recursive Pattern
		words := strings.Fields(line)
		if len(words) != 8 {
			continue
		}

		subjectPath := words[1]
		objectPath := words[3]

		permissive := words[4]

		directory := words[5]
		recursive := words[6]

		if permissive == "true" {
			continue
		}

		// if err := kl.RunCommandAndWaitWithErr(se.SELinuxTemplatePath+"/restore.sh", []string{subjectPath, objectPath, directory, recursive}); err != nil {
		// 	se.Logger.Warnf("Unable to restore the original label of %s", objectPath)
		// 	res = false
		// }

		if output, err := kl.GetCommandOutputWithErr(se.SELinuxTemplatePath+"/restore.sh", []string{subjectPath, objectPath, directory, recursive}); err != nil {
			se.Logger.Warnf("Unable to restore the original label of %s:\n%s", objectPath, output)
			res = false
		}
	}

	return res
}

// UpdateSELinuxLabels Function
func (se *SELinuxEnforcer) UpdateSELinuxLabels(profilePath string) bool {
	if _, err := os.Stat(filepath.Clean(profilePath)); err != nil {
		se.Logger.Warnf("Unable to find %s", profilePath)
		return false
	}

	if ok := se.RestoreSELinuxLabels(profilePath); !ok {
		se.Logger.Warnf("Unable to restore the original SELinux labels affected by %s", profilePath)
	}

	if err := kl.CopyFile(profilePath, profilePath+".old"); err != nil {
		se.Logger.Warnf("Unable to create %s.old", profilePath)
	}

	profile, err := ioutil.ReadFile(filepath.Clean(profilePath))
	if err != nil {
		se.Logger.Warnf("Unable to read %s", profilePath)
		return false
	}

	res := true

	for _, line := range strings.Split(string(profile), "\n") {
		// fields: SubjectLabel SubjectPath ObjectLabel ObjectPath Permissive Directory Recursive Pattern
		words := strings.Fields(line)
		if len(words) != 8 {
			continue
		}

		subjectLabel := words[0]
		subjectPath := words[1]

		objectLabel := words[2]
		objectPath := words[3]

		permissive := words[4]

		directory := words[5]
		recursive := words[6]

		if permissive == "true" {
			continue
		}

		// if err := kl.RunCommandAndWaitWithErr(se.SELinuxTemplatePath+"/update.sh", []string{subjectLabel, subjectPath, objectLabel, objectPath, directory, recursive}); err != nil {
		// 	se.Logger.Warnf("Unable to update the SELinux label of %s", objectPath)
		// 	res = false
		// }

		if output, err := kl.GetCommandOutputWithErr(se.SELinuxTemplatePath+"/update.sh", []string{subjectLabel, subjectPath, objectLabel, objectPath, directory, recursive}); err != nil {
			se.Logger.Warnf("Unable to update the SELinux label of %s:\n%s", objectPath, output)
			res = false
		}
	}

	return res
}
