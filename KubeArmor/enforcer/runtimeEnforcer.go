// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// RuntimeEnforcer Structure
type RuntimeEnforcer struct {
	// logger
	Logger *fd.Feeder

	// LSM type
	EnforcerType string

	// LSMs
	appArmorEnforcer *AppArmorEnforcer
	seLinuxEnforcer  *SELinuxEnforcer
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(node tp.Node, logger *fd.Feeder) *RuntimeEnforcer {
	re := &RuntimeEnforcer{}

	re.Logger = logger

	if !kl.IsK8sLocal() {
		// mount securityfs
		if err := kl.RunCommandAndWaitWithErr("mount", []string{"-t", "securityfs", "securityfs", "/sys/kernel/security"}); err != nil {
			re.Logger.Errf("Failed to mount securityfs (%s)", err.Error())
		}
	}

	lsm := []byte{}
	lsmPath := "/sys/kernel/security/lsm"

	if _, err := os.Stat(filepath.Clean(lsmPath)); err == nil {
		lsm, err = ioutil.ReadFile(lsmPath)
		if err != nil {
			re.Logger.Errf("Failed to read /sys/kernel/security/lsm (%s)", err.Error())
			return nil
		}
	}

	re.EnforcerType = string(lsm)

	if strings.Contains(re.EnforcerType, "apparmor") {
		re.appArmorEnforcer = NewAppArmorEnforcer(node, logger)
		if re.appArmorEnforcer != nil {
			re.Logger.Print("Initialized AppArmor Enforcer")
			re.EnforcerType = "AppArmor"
		} else {
			return nil
		}
	} else if strings.Contains(re.EnforcerType, "selinux") {
		if kl.IsK8sLocal() {
			re.seLinuxEnforcer = NewSELinuxEnforcer(logger)
			if re.seLinuxEnforcer != nil {
				re.Logger.Print("Initialized SELinux Enforcer")
				re.EnforcerType = "SELinux"
			} else {
				return nil
			}
		} else {
			return nil
		}
	} else {
		return nil
	}

	return re
}

// UpdateAppArmorProfiles Function
func (re *RuntimeEnforcer) UpdateAppArmorProfiles(action string, profiles map[string]string) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "AppArmor" {
		for _, profile := range profiles {
			if profile == "unconfined" {
				continue
			}

			if action == "ADDED" {
				re.appArmorEnforcer.RegisterAppArmorProfile(profile)
			} else if action == "DELETED" {
				re.appArmorEnforcer.UnregisterAppArmorProfile(profile)
			}
		}
	}
}

// UpdateSELinuxProfiles Function
func (re *RuntimeEnforcer) UpdateSELinuxProfiles(action string, profiles map[string]string, hostVolumes []tp.HostVolumeMount) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "SELinux" {
		for k, v := range profiles {
			if strings.HasPrefix(k, "selinux-") { // selinux- + [container_name]
				containerName := strings.Split(k, "selinux-")[1]
				if action == "ADDED" {
					re.seLinuxEnforcer.RegisterSELinuxProfile(containerName, hostVolumes, v)
				} else if action == "DELETED" {
					re.seLinuxEnforcer.UnregisterSELinuxProfile(v)
				}
			}
		}
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "AppArmor" {
		re.appArmorEnforcer.UpdateSecurityPolicies(endPoint)
	} else if re.EnforcerType == "SELinux" {
		re.seLinuxEnforcer.UpdateSecurityPolicies(endPoint)
	}
}

// UpdateHostSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "AppArmor" {
		re.appArmorEnforcer.UpdateHostSecurityPolicies(secPolicies)
	} else if re.EnforcerType == "SELinux" {
		re.seLinuxEnforcer.UpdateHostSecurityPolicies(secPolicies)
	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() error {
	// skip if runtime enforcer is not active
	if re == nil {
		return nil
	}

	errorLSM := false

	if re.EnforcerType == "AppArmor" {
		if re.appArmorEnforcer != nil {
			if err := re.appArmorEnforcer.DestroyAppArmorEnforcer(); err != nil {
				re.Logger.Err(err.Error())
				errorLSM = true
			} else {
				re.Logger.Print("Destroyed AppArmor Enforcer")
			}
		}
	} else if re.EnforcerType == "selinux" {
		if re.seLinuxEnforcer != nil {
			if err := re.seLinuxEnforcer.DestroySELinuxEnforcer(); err != nil {
				re.Logger.Err(err.Error())
				errorLSM = true
			} else {
				re.Logger.Print("Destroyed SELinux Enforcer")
			}
		}
	}

	if errorLSM {
		return fmt.Errorf("failed to destroy RuntimeEnforcer (%s)", re.EnforcerType)
	}

	return nil
}
