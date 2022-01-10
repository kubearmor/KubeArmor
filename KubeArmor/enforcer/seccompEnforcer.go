// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"os"
	"sync"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ====================== //
// == Seccomp Enforcer == //
// ====================== //

// SeccompEnforcer Structure
type SeccompEnforcer struct {
	// logs
	Logger *fd.Feeder

	// profiles for containers
	SeccompProfiles     map[string]int
	SeccompProfilesLock *sync.RWMutex
}

// NewSeccompEnforcer Function
func NewSeccompEnforcer(node tp.Node, logger *fd.Feeder) *SeccompEnforcer {
	se := &SeccompEnforcer{}

	// logs
	se.Logger = logger

	// profiles
	se.SeccompProfiles = map[string]int{}
	se.SeccompProfilesLock = &sync.RWMutex{}

	se.Logger.Printf("seccomp enforcer inited")

	return se
}

// DestroySeccompEnforcer Function
func (se *SeccompEnforcer) DestroySeccompEnforcer() error {
	// skip if SeccompEnforcer is not active
	if se == nil {
		return nil
	}

	for profile := range se.SeccompProfiles {
		se.UnregisterSeccompProfile(profile)
	}

	return nil
}

// ================================= //
// == Seccomp Profile Management == //
// ================================= //

// RegisterSeccompProfile Function
func (se *SeccompEnforcer) RegisterSeccompProfile(profileName string) bool {
	// skip if SeccompEnforcer is not active
	if se == nil {
		return true
	}
	se.Logger.Printf("register seccomp profile profileName:%s", profileName)

	se.SeccompProfilesLock.Lock()
	defer se.SeccompProfilesLock.Unlock()

	fname := SeccompFileName(profileName)

	if _, err := os.Stat(fname); err == nil {
		// TODO
		// se.Logger.Errf("NOT IMPLEMENTED MULTIPLE SECCOMP PROFILES")
		return true
	}

	newFile, err := os.Create(fname)
	if err != nil {
		se.Logger.Errf("Failed to create a profile (%s, %s)", fname, err.Error())
		return false
	}
	defer newFile.Close()

	str := `
{
    "defaultAction": "SCMP_ACT_LOG"
}
`
	if _, err = newFile.WriteString(str); err != nil {
		se.Logger.Errf("Failed to initialize the profile (%s, %s)",
			fname, err.Error())
	}

	if err := newFile.Close(); err != nil {
		se.Logger.Errf("Failed to close the profile (%s, %s)",
			fname, err.Error())
	}

	return true
}

// UnregisterSeccompProfile Function
func (se *SeccompEnforcer) UnregisterSeccompProfile(profileName string) bool {
	// skip if SeccompEnforcer is not active
	if se == nil {
		return true
	}
	se.Logger.Printf("unregister seccomp profile profileName:%s", profileName)

	se.SeccompProfilesLock.Lock()
	defer se.SeccompProfilesLock.Unlock()

	return true
}

// ================================= //
// == Seccomp Policy Enforcement == //
// ================================= //

// UpdateSeccompProfile Function
func (se *SeccompEnforcer) UpdateSeccompProfile(endPoint tp.EndPoint, seccompProfile string, seccompPolicies []tp.SeccompPolicy) {
	if newProfile, ok := se.GenerateSeccompProfile(seccompProfile, seccompPolicies); ok {
		newfile, err := os.Create(SeccompFileName(seccompProfile))
		if err != nil {
			se.Logger.Err(err.Error())
			return
		}

		if _, err := newfile.WriteString(newProfile); err != nil {
			se.Logger.Err(err.Error())

			if err := newfile.Close(); err != nil {
				se.Logger.Err(err.Error())
			}

			return
		}

		if err := newfile.Sync(); err != nil {
			se.Logger.Err(err.Error())

			if err := newfile.Close(); err != nil {
				se.Logger.Err(err.Error())
			}

			return
		}

		if err := newfile.Close(); err != nil {
			se.Logger.Err(err.Error())
		}
	}
}

// UpdateSeccompPolicies Function
func (se *SeccompEnforcer) UpdateSeccompPolicies(endPoint tp.EndPoint) {
	// skip if SeccompEnforcer is not active
	if se == nil {
		return
	}
	seccompProfiles := []string{}

	for _, seccompProfile := range endPoint.SeccompProfiles {
		if !kl.ContainsElement(seccompProfiles, seccompProfile) {
			seccompProfiles = append(seccompProfiles, seccompProfile)
		}
	}

	if cfg.GlobalCfg.Seccomp {
		for _, seccompProfile := range seccompProfiles {
			se.UpdateSeccompProfile(endPoint, seccompProfile, endPoint.SeccompPolicies)
		}
	} else { // PolicyDisabled
		for _, seccompProfile := range seccompProfiles {
			se.UpdateSeccompProfile(endPoint, seccompProfile, []tp.SeccompPolicy{})
		}
	}
}
