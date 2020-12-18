package enforcer

import (
	"strings"

	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// RuntimeEnforcer Structure
type RuntimeEnforcer struct {
	enforcerType string

	// LSMs
	krsiEnforcer     *KRSIEnforcer
	appArmorEnforcer *AppArmorEnforcer
	seLinuxEnforcer  *SELinuxEnforcer
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(homeDir string) *RuntimeEnforcer {
	re := &RuntimeEnforcer{}

	// AppArmor by default
	re.enforcerType = "AppArmor"

	if strings.Contains(re.enforcerType, "KRSI") {
		re.krsiEnforcer = NewKRSIEnforcer()
	}

	if strings.Contains(re.enforcerType, "AppArmor") {
		re.appArmorEnforcer = NewAppArmorEnforcer(homeDir)
	}

	if strings.Contains(re.enforcerType, "SELinux") {
		re.seLinuxEnforcer = NewSELinuxEnforcer()
	}

	return re
}

// UpdateSecurityProfiles Function
func (re *RuntimeEnforcer) UpdateSecurityProfiles(action string, pod tp.K8sPod) {
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

		for _, profile := range appArmorProfiles {
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
	if strings.Contains(re.enforcerType, "KRSI") {
		re.krsiEnforcer.UpdateSecurityPolicies(conGroup)
	}

	if strings.Contains(re.enforcerType, "AppArmor") {
		re.appArmorEnforcer.UpdateSecurityPolicies(conGroup)
	}

	if strings.Contains(re.enforcerType, "SELinux") {
		re.seLinuxEnforcer.UpdateSecurityPolicies(conGroup)
	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() {
	if strings.Contains(re.enforcerType, "KRSI") {
		re.krsiEnforcer.DestroyKRSIEnforcer()
	}

	if strings.Contains(re.enforcerType, "AppArmor") {
		re.appArmorEnforcer.DestroyAppArmorEnforcer()
	}

	if strings.Contains(re.enforcerType, "SELinux") {
		re.seLinuxEnforcer.DestroySELinuxEnforcer()
	}
}
