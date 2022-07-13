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
	be "github.com/kubearmor/KubeArmor/KubeArmor/enforcer/bpflsm"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// RuntimeEnforcer Structure
type RuntimeEnforcer struct {
	// logger
	Logger *fd.Feeder

	// LSM type
	EnforcerType string

	// LSM - BPFLSM
	bpfEnforcer *be.BPFEnforcer

	// LSM - AppArmor
	appArmorEnforcer *AppArmorEnforcer

	// LSM - SELinux
	seLinuxEnforcer *SELinuxEnforcer
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(node tp.Node, logger *fd.Feeder) *RuntimeEnforcer {
	re := &RuntimeEnforcer{}

	re.Logger = logger

	if !kl.IsK8sLocal() {
		// mount securityfs
		if err := kl.RunCommandAndWaitWithErr("mount", []string{"-t", "securityfs", "securityfs", "/sys/kernel/security"}); err != nil {
			if _, err := os.Stat(filepath.Clean("/sys/kernel/security")); err != nil {
				re.Logger.Errf("Failed to read /sys/kernel/security (%s)", err.Error())
				return nil
			}
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

	lsms := string(lsm)
	re.Logger.Printf("Supported LSMs: %s", lsms)

	if strings.Contains(lsms, "bpf") {
		var err error
		re.bpfEnforcer, err = be.NewBPFEnforcer(node, logger)
		if re.bpfEnforcer != nil {
			if err != nil {
				re.Logger.Print("Error Initialising BPF LSM Enforcer, Cleaning Up")
				if err := re.bpfEnforcer.DestroyBPFEnforcer(); err != nil {
					re.Logger.Err(err.Error())
				} else {
					re.Logger.Print("Destroyed BPFLSM Enforcer")
				}
			} else {
				re.Logger.Print("Initialized BPF LSM Enforcer")
				re.EnforcerType = "BPFLSM"
				logger.UpdateEnforcer(re.EnforcerType)
				return re
			}
		}

	}

	// Fallback to Other LSMs if failure during BPF Enforcer initialisation
	if strings.Contains(lsms, "apparmor") {
		re.appArmorEnforcer = NewAppArmorEnforcer(node, logger)
		if re.appArmorEnforcer != nil {
			re.Logger.Print("Initialized AppArmor Enforcer")
			re.EnforcerType = "AppArmor"
			logger.UpdateEnforcer(re.EnforcerType)
			return re
		}
	} else if strings.Contains(lsms, "selinux") {
		if !kl.IsInK8sCluster() {
			re.seLinuxEnforcer = NewSELinuxEnforcer(node, logger)
			if re.seLinuxEnforcer != nil {
				re.Logger.Print("Initialized SELinux Enforcer")
				re.EnforcerType = "SELinux"
				logger.UpdateEnforcer(re.EnforcerType)
				return re
			}
		}
	}

	return nil
}

// RegisterContainer registers container identifiers to BPFEnforcer Map
func (re *RuntimeEnforcer) RegisterContainer(containerID string, pidns, mntns uint32) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "BPFLSM" {
		re.bpfEnforcer.AddContainerIDToMap(containerID, pidns, mntns)
	}
}

// UnregisterContainer removes container identifiers from BPFEnforcer Map
func (re *RuntimeEnforcer) UnregisterContainer(containerID string) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "BPFLSM" {
		re.bpfEnforcer.DeleteContainerIDFromMap(containerID)
	}
}

// UpdateAppArmorProfiles Function
func (re *RuntimeEnforcer) UpdateAppArmorProfiles(podName, action string, profiles map[string]string) {
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
				re.appArmorEnforcer.RegisterAppArmorProfile(podName, profile)
			} else if action == "DELETED" {
				re.appArmorEnforcer.UnregisterAppArmorProfile(podName, profile)
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

	if re.EnforcerType == "BPFLSM" {
		re.bpfEnforcer.UpdateSecurityPolicies(endPoint)
	} else if re.EnforcerType == "AppArmor" {
		re.appArmorEnforcer.UpdateSecurityPolicies(endPoint)
	} else if re.EnforcerType == "SELinux" {
		// do nothing
	}
}

// UpdateHostSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	if re.EnforcerType == "BPFLSM" {
		re.bpfEnforcer.UpdateHostSecurityPolicies(secPolicies)
	} else if re.EnforcerType == "AppArmor" {
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

	if re.EnforcerType == "BPFLSM" {
		if re.bpfEnforcer != nil {
			if err := re.bpfEnforcer.DestroyBPFEnforcer(); err != nil {
				re.Logger.Err(err.Error())
				errorLSM = true
			} else {
				re.Logger.Print("Destroyed BPFLSM Enforcer")
			}
		}
	} else if re.EnforcerType == "AppArmor" {
		if re.appArmorEnforcer != nil {
			if err := re.appArmorEnforcer.DestroyAppArmorEnforcer(); err != nil {
				re.Logger.Err(err.Error())
				errorLSM = true
			} else {
				re.Logger.Print("Destroyed AppArmor Enforcer")
			}
		}
	} else if re.EnforcerType == "SELinux" {
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

	// Reset Enforcer to nil if no errors during clean up
	re = nil
	return nil
}
