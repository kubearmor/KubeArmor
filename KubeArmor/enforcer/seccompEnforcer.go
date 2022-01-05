// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"sync"

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
// == Security Policy Enforcement == //
// ================================= //

// UpdateSeccompProfile Function
func (se *SeccompEnforcer) UpdateSeccompProfile(endPoint tp.EndPoint, appArmorProfile string, securityPolicies []tp.SecurityPolicy) {
	/*
		if policyCount, newProfile, ok := se.GenerateSeccompProfile(appArmorProfile, securityPolicies); ok {
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

			if err := newfile.Close(); err != nil {
				ae.Logger.Err(err.Error())
			}
		}
	*/
}

// UpdateSeccompPolicies Function
func (se *SeccompEnforcer) UpdateSeccompPolicies(endPoint tp.EndPoint) {
	// skip if SeccompEnforcer is not active
	if se == nil {
		return
	}
}
