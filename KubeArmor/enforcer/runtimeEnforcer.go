package enforcer

import (
	"fmt"
	"strings"

	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
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
func NewRuntimeEnforcer() *RuntimeEnforcer {
	re := &RuntimeEnforcer{}

	checkLSM := false

	// AppArmor by default
	re.enforcerType = "AppArmor"

	if strings.Contains(re.enforcerType, "KRSI") {
		re.krsiEnforcer = NewKRSIEnforcer()
		if re.krsiEnforcer != nil {
			checkLSM = true
		}
	}

	if strings.Contains(re.enforcerType, "AppArmor") {
		re.appArmorEnforcer = NewAppArmorEnforcer()
		if re.appArmorEnforcer != nil {
			checkLSM = true
		}
	}

	if strings.Contains(re.enforcerType, "SELinux") {
		re.seLinuxEnforcer = NewSELinuxEnforcer()
		if re.seLinuxEnforcer != nil {
			checkLSM = true
		}
	}

	if !checkLSM {
		return nil
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
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() error {
	errorLSM := ""

	if strings.Contains(re.enforcerType, "KRSI") {
		if re.krsiEnforcer != nil {
			if err := re.krsiEnforcer.DestroyKRSIEnforcer(); err != nil {
				kg.Err(err.Error())

				if errorLSM == "" {
					errorLSM = "KRSI"
				} else {
					errorLSM = errorLSM + "|KRSI"
				}
			}
		}
	}

	if strings.Contains(re.enforcerType, "AppArmor") {
		if re.appArmorEnforcer != nil {
			if err := re.appArmorEnforcer.DestroyAppArmorEnforcer(); err != nil {
				kg.Err(err.Error())

				if errorLSM == "" {
					errorLSM = "AppArmor"
				} else {
					errorLSM = errorLSM + "|AppArmor"
				}
			}
		}
	}

	if strings.Contains(re.enforcerType, "SELinux") {
		if re.seLinuxEnforcer != nil {
			if err := re.seLinuxEnforcer.DestroySELinuxEnforcer(); err != nil {
				kg.Err(err.Error())

				if errorLSM == "" {
					errorLSM = "SELinux"
				} else {
					errorLSM = errorLSM + "|SELinux"
				}
			}
		}
	}

	if errorLSM != "" {
		return fmt.Errorf("Failed to destroy RuntimeEnforcer (%s)", errorLSM)
	}

	return nil
}
