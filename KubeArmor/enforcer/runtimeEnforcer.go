// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

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
	enableLSM    bool
	enforcerType string

	// LSMs
	appArmorEnforcer *AppArmorEnforcer
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(feeder *fd.Feeder) *RuntimeEnforcer {
	re := &RuntimeEnforcer{}

	re.LogFeeder = feeder
	re.enableLSM = false

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

	re.enforcerType = string(lsm)

	if strings.Contains(re.enforcerType, "apparmor") {
		re.appArmorEnforcer = NewAppArmorEnforcer(feeder)
		if re.appArmorEnforcer != nil {
			re.LogFeeder.Print("Initialized AppArmor Enforcer")
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
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	if strings.Contains(re.enforcerType, "apparmor") {
		re.appArmorEnforcer.UpdateSecurityPolicies(conGroup)
	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() error {
	errorLSM := ""

	if strings.Contains(re.enforcerType, "apparmor") {
		if re.appArmorEnforcer != nil {
			if err := re.appArmorEnforcer.DestroyAppArmorEnforcer(); err != nil {
				re.LogFeeder.Err(err.Error())
				errorLSM = "AppArmor"
			} else {
				re.LogFeeder.Print("Destroyed AppArmor Enforcer")
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
	if strings.Contains(re.enforcerType, "apparmor") {
		return "apparmor"
	}

	return "None"
}
