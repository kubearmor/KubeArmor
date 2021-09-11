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
	// logs
	LogFeeder *fd.Feeder

	// LSM type
	EnforcerType string

	// LSMs
	appArmorEnforcer *AppArmorEnforcer
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(feeder *fd.Feeder) *RuntimeEnforcer {
	re := &RuntimeEnforcer{}

	re.LogFeeder = feeder

	if !kl.IsK8sLocal() {
		// mount securityfs
		if err := kl.RunCommandAndWaitWithErr("mount", []string{"-t", "securityfs", "securityfs", "/sys/kernel/security"}); err != nil {
			re.LogFeeder.Err(err.Error())
		}
	}

	lsm := []byte{}
	lsmPath := "/sys/kernel/security/lsm"

	if _, err := os.Stat(filepath.Clean(lsmPath)); err == nil {
		lsm, err = ioutil.ReadFile(lsmPath)
		if err != nil {
			re.LogFeeder.Errf("Failed to read /sys/kernel/security/lsm (%s)", err.Error())
			return re
		}
	}

	re.EnforcerType = string(lsm)

	if strings.Contains(re.EnforcerType, "apparmor") {
		re.appArmorEnforcer = NewAppArmorEnforcer(feeder)
		if re.appArmorEnforcer != nil {
			re.LogFeeder.Print("Initialized AppArmor Enforcer")
			re.EnforcerType = "AppArmor"
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
	if re.EnforcerType == "AppArmor" {
		for _, profile := range profiles {
			if action == "ADDED" {
				re.appArmorEnforcer.RegisterAppArmorProfile(profile)
			} else if action == "DELETED" {
				re.appArmorEnforcer.UnregisterAppArmorProfile(profile)
			}
		}
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	if re.EnforcerType == "AppArmor" {
		re.appArmorEnforcer.UpdateSecurityPolicies(conGroup)
	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() error {
	errorLSM := false

	if re.EnforcerType == "AppArmor" {
		if re.appArmorEnforcer != nil {
			if err := re.appArmorEnforcer.DestroyAppArmorEnforcer(); err != nil {
				re.LogFeeder.Err(err.Error())
				errorLSM = true
			} else {
				re.LogFeeder.Print("Destroyed AppArmor Enforcer")
			}
		}
	}

	if errorLSM {
		return fmt.Errorf("failed to destroy RuntimeEnforcer (%s)", re.EnforcerType)
	}

	return nil
}
