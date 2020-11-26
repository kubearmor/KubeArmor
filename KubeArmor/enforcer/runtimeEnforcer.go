package enforcer

import (
	"strings"
	"sync"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// RuntimeEnforcer Structure
type RuntimeEnforcer struct {
	enforcerType string

	// LSMs
	appArmorEnforcer *AppArmorEnforcer

	// AppArmor profiles
	AppArmorProfiles     []string
	AppArmorProfilesLock *sync.Mutex
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(homeDir string) *RuntimeEnforcer {
	re := &RuntimeEnforcer{}

	// AppArmor by default
	re.enforcerType = "AppArmor"

	if strings.Contains(re.enforcerType, "KRSI") {
		//
	}

	if strings.Contains(re.enforcerType, "AppArmor") {
		re.AppArmorProfiles = []string{}
		re.AppArmorProfilesLock = &sync.Mutex{}
		re.appArmorEnforcer = NewAppArmorEnforcer(homeDir)
	}

	if strings.Contains(re.enforcerType, "SELinux") {
		//
	}

	return re
}

// UpdateSecurityProfiles Function
func (re *RuntimeEnforcer) UpdateSecurityProfiles(action string, pod tp.K8sPod) {
	if strings.Contains(re.enforcerType, "KRSI") {
		//
	}

	if strings.Contains(re.enforcerType, "AppArmor") {
		appArmorProfiles := []string{}

		for k, v := range pod.Annotations {
			if strings.Contains(k, "container.apparmor.security.beta.kubernetes.io") {
				words := strings.Split(v, "/")
				if len(words) == 2 {
					appArmorProfiles = append(appArmorProfiles, words[1])
				}
			}
		}

		re.AppArmorProfilesLock.Lock()

		for _, profile := range appArmorProfiles {
			if action == "ADDED" {
				if !kl.ContainsElement(re.AppArmorProfiles, profile) {
					re.AppArmorProfiles = append(re.AppArmorProfiles, profile)
				}

				// register profile
				re.appArmorEnforcer.RegisterAppArmorProfile(profile)

			} else if action == "DELETED" {
				if kl.ContainsElement(re.AppArmorProfiles, profile) {
					re.AppArmorProfiles = kl.RemoveStrFromSlice(re.AppArmorProfiles, profile)
				}

				// unregister profile
				re.appArmorEnforcer.UnregisterAppArmorProfile(profile)
			}
		}

		re.AppArmorProfilesLock.Unlock()
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	if strings.Contains(re.enforcerType, "KRSI") {
		//
	}

	if strings.Contains(re.enforcerType, "AppArmor") {
		re.appArmorEnforcer.UpdateSecurityPolicies(conGroup)
	}

	if strings.Contains(re.enforcerType, "SELinux") {
		//
	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() {
	if strings.Contains(re.enforcerType, "KRSI") {
		//
	}

	if strings.Contains(re.enforcerType, "AppArmor") {
		re.appArmorEnforcer.DestroyAppArmorEnforcer()
	}

	if strings.Contains(re.enforcerType, "SELinux") {
		//
	}
}
