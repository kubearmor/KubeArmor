// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"io/ioutil"
	"os"
	"path/filepath"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func SeccompFileName(profileName string) string {
	return filepath.Clean("/var/lib/kubelet/seccomp/" + profileName)
}

// == //

func GenerateSeccompProfile(seccompPolicies []tp.SeccompPolicy) string {
	return ""
}

// GenerateSeccompProfile Function
func (se *SeccompEnforcer) GenerateSeccompProfile(seccompProfile string, seccompPolicies []tp.SeccompPolicy) (string, bool) {

	fname := filepath.Clean(SeccompFileName(seccompProfile)) // filepath.Clean is done again (SeccompFileName already has it) to keep lint happy!

	if _, err := os.Stat(fname); os.IsNotExist(err) {
		return err.Error(), false
	}

	// get the old profile

	profile, err := ioutil.ReadFile(fname)
	if err != nil {
		return err.Error(), false
	}
	oldProfile := string(profile)

	// generate a profile body

	newProfile := GenerateSeccompProfile(seccompPolicies)

	// check the new profile with the old profile

	if newProfile != oldProfile {
		return newProfile, true
	}

	return "", false
}
