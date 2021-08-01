// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package enforcer

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// RuntimeEnforcer Structure
type RuntimeEnforcer struct {
	// logs
	LogFeeder *fd.Feeder

	// LSM type
	enableLSM    bool
	enforcerType string

	// LSMs
	krsiEnforcer     *KRSIEnforcer
	appArmorEnforcer *AppArmorEnforcer
	seLinuxEnforcer  *SELinuxEnforcer
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(feeder *fd.Feeder, enableAuditd, enableHostPolicy bool) *RuntimeEnforcer {
	re := &RuntimeEnforcer{}

	re.LogFeeder = feeder
	re.enableLSM = false

	if !kl.IsK8sLocal() {
		// mount securityfs
		kl.GetCommandOutputWithoutErr("mount", []string{"-t", "securityfs", "securityfs", "/sys/kernel/security"})
	}

	lsm := []byte{}
	lsmPath := "/sys/kernel/security/lsm"

	if _, err := os.Stat(lsmPath); err == nil {
		lsm, err = ioutil.ReadFile(lsmPath)
		if err != nil {
			re.LogFeeder.Errf("Failed to read /sys/kernel/security/lsm (%s)", err.Error())
			return re
		}
	}

	re.enforcerType = string(lsm)

	if strings.Contains(re.enforcerType, "krsi") {
		re.krsiEnforcer = NewKRSIEnforcer(feeder)
		if re.krsiEnforcer != nil {
			re.LogFeeder.Print("Initialized KRSI Enforcer")
			re.enableLSM = true
		}
	}

	if strings.Contains(re.enforcerType, "apparmor") {
		re.appArmorEnforcer = NewAppArmorEnforcer(feeder, enableAuditd, enableHostPolicy)
		if re.appArmorEnforcer != nil {
			re.LogFeeder.Print("Initialized AppArmor Enforcer")
			re.enableLSM = true
		}
	}

	if strings.Contains(re.enforcerType, "selinux") {
		re.seLinuxEnforcer = NewSELinuxEnforcer(feeder)
		if re.seLinuxEnforcer != nil {
			re.LogFeeder.Print("Initialized SELinux Enforcer")
			re.enableLSM = true
		}
	}

	return re
}

// UpdateSecurityProfiles Function
func (re *RuntimeEnforcer) UpdateSecurityProfiles(action string, pod tp.K8sPod, full bool) {
	if strings.Contains(re.enforcerType, "apparmor") {
		appArmorProfiles := []string{}

		for k, v := range pod.Annotations {
			if strings.Contains(k, "container.apparmor.security.beta.kubernetes.io") {
				words := strings.Split(v, "/")
				if len(words) == 2 {
					appArmorProfiles = append(appArmorProfiles, words[1])
				}
			}
		}

		for _, profile := range appArmorProfiles {
			if action == "ADDED" {
				re.appArmorEnforcer.RegisterAppArmorProfile(profile, full)
			} else if action == "DELETED" {
				re.appArmorEnforcer.UnregisterAppArmorProfile(profile, full)
			}
		}
	} else if strings.Contains(re.enforcerType, "selinux") {
		for k, selinuxProfile := range pod.Metadata {
			if strings.HasPrefix(k, "selinux-") { // selinux- + [container_name]
				containerName := strings.Split(k, "selinux-")[1]
				if action == "ADDED" {
					re.seLinuxEnforcer.RegisterSELinuxProfile(pod, containerName, selinuxProfile)
				} else if action == "DELETED" {
					re.seLinuxEnforcer.UnregisterSELinuxProfile(pod, selinuxProfile)
				}
			}
		}
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	if strings.Contains(re.enforcerType, "krsi") {
		re.krsiEnforcer.UpdateSecurityPolicies(conGroup)
	}

	if strings.Contains(re.enforcerType, "apparmor") {
		re.appArmorEnforcer.UpdateSecurityPolicies(conGroup)
	}

	if strings.Contains(re.enforcerType, "selinux") {
		re.seLinuxEnforcer.UpdateSecurityPolicies(conGroup)
	}
}

// UpdateHostSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	if strings.Contains(re.enforcerType, "krsi") {
		re.krsiEnforcer.UpdateHostSecurityPolicies(secPolicies)
	}

	if strings.Contains(re.enforcerType, "apparmor") {
		re.appArmorEnforcer.UpdateHostSecurityPolicies(secPolicies)
	}

	if strings.Contains(re.enforcerType, "selinux") {
		re.seLinuxEnforcer.UpdateHostSecurityPolicies(secPolicies)
	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() error {
	errorLSM := ""

	if strings.Contains(re.enforcerType, "krsi") {
		if re.krsiEnforcer != nil {
			if err := re.krsiEnforcer.DestroyKRSIEnforcer(); err != nil {
				re.LogFeeder.Err(err.Error())

				if errorLSM == "" {
					errorLSM = "KRSI"
				} else {
					errorLSM = errorLSM + "|KRSI"
				}
			} else {
				re.LogFeeder.Print("Destroyed KRSI Enforcer")
			}
		}
	}

	if strings.Contains(re.enforcerType, "apparmor") {
		if re.appArmorEnforcer != nil {
			if err := re.appArmorEnforcer.DestroyAppArmorEnforcer(); err != nil {
				re.LogFeeder.Err(err.Error())

				if errorLSM == "" {
					errorLSM = "AppArmor"
				} else {
					errorLSM = errorLSM + "|AppArmor"
				}
			} else {
				re.LogFeeder.Print("Destroyed AppArmor Enforcer")
			}
		}
	}

	if strings.Contains(re.enforcerType, "selinux") {
		if re.seLinuxEnforcer != nil {
			if err := re.seLinuxEnforcer.DestroySELinuxEnforcer(); err != nil {
				re.LogFeeder.Err(err.Error())

				if errorLSM == "" {
					errorLSM = "SELinux"
				} else {
					errorLSM = errorLSM + "|SELinux"
				}
			} else {
				re.LogFeeder.Print("Destroyed SELinux Enforcer")
			}
		}
	}

	if errorLSM != "" {
		return fmt.Errorf("failed to destroy RuntimeEnforcer (%s)", errorLSM)
	}

	return nil
}

// IsEnabled Function
func (re *RuntimeEnforcer) IsEnabled() bool {
	return re.enableLSM
}

// GetEnforcerType Function
func (re *RuntimeEnforcer) GetEnforcerType() string {
	if strings.Contains(re.enforcerType, "krsi") {
		return "krsi"
	}

	if strings.Contains(re.enforcerType, "apparmor") {
		return "apparmor"
	}

	if strings.Contains(re.enforcerType, "selinux") {
		return "selinux"
	}

	return "None"
}
