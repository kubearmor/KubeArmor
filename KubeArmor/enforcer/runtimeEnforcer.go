package enforcer

import (
	"fmt"
	"io/ioutil"
	"strings"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// RuntimeEnforcer Structure
type RuntimeEnforcer struct {
	// logs
	LogFeeder *fd.Feeder

	// LSM type
	enableLSM    bool
	enforcerType string

	// LSMs
	krsiEnforcer     *KRSIEnforcer
	appArmorEnforcer *AppArmorEnforcer
	seLinuxEnforcer  *SELinuxEnforcer
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(feeder *fd.Feeder) *RuntimeEnforcer {
	re := &RuntimeEnforcer{}

	re.LogFeeder = feeder

	if !kl.IsK8sLocal() {
		// mount securityfs
		kl.GetCommandOutputWithoutErr("mount", []string{"-t", "securityfs", "securityfs", "/sys/kernel/security"})
	}

	lsm, err := ioutil.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		re.LogFeeder.Errf("Failed to read /sys/kernel/security/lsm (%s)", err.Error())
	}

	re.enableLSM = false
	re.enforcerType = string(lsm)

	if strings.Contains(re.enforcerType, "krsi") {
		re.krsiEnforcer = NewKRSIEnforcer(feeder)
		if re.krsiEnforcer != nil {
			re.LogFeeder.Print("Initialized KRSI Enforcer")
			re.enableLSM = true
		}
	}

	if strings.Contains(re.enforcerType, "apparmor") {
		re.appArmorEnforcer = NewAppArmorEnforcer(feeder)
		if re.appArmorEnforcer != nil {
			re.LogFeeder.Print("Initialized AppArmor Enforcer")
			re.enableLSM = true
		}
	}

	if strings.Contains(re.enforcerType, "selinux") {
		re.seLinuxEnforcer = NewSELinuxEnforcer(feeder)
		if re.seLinuxEnforcer != nil {
			re.LogFeeder.Print("Initialized SELinux Enforcer")
			re.enableLSM = true
		}
	}

	if !re.enableLSM {
		return nil
	}

	return re
}

// UpdateSecurityProfiles Function
func (re *RuntimeEnforcer) UpdateSecurityProfiles(action string, pod tp.K8sPod) {
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
				re.appArmorEnforcer.RegisterAppArmorProfile(profile)
			} else if action == "DELETED" {
				re.appArmorEnforcer.UnregisterAppArmorProfile(profile)
			}
		}
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	if strings.Contains(re.enforcerType, "krsi") {
		re.krsiEnforcer.UpdateSecurityPolicies(conGroup)
	}

	if strings.Contains(re.enforcerType, "apparmor") {
		re.appArmorEnforcer.UpdateSecurityPolicies(conGroup)
	}

	if strings.Contains(re.enforcerType, "selinux") {
		re.seLinuxEnforcer.UpdateSecurityPolicies(conGroup)
	}
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcer) DestroyRuntimeEnforcer() error {
	errorLSM := ""

	if strings.Contains(re.enforcerType, "krsi") {
		if re.krsiEnforcer != nil {
			if err := re.krsiEnforcer.DestroyKRSIEnforcer(); err != nil {
				re.LogFeeder.Err(err.Error())

				if errorLSM == "" {
					errorLSM = "KRSI"
				} else {
					errorLSM = errorLSM + "|KRSI"
				}
			} else {
				re.LogFeeder.Print("Destroyed KRSI Enforcer")
			}
		}
	}

	if strings.Contains(re.enforcerType, "apparmor") {
		if re.appArmorEnforcer != nil {
			if err := re.appArmorEnforcer.DestroyAppArmorEnforcer(); err != nil {
				re.LogFeeder.Err(err.Error())

				if errorLSM == "" {
					errorLSM = "AppArmor"
				} else {
					errorLSM = errorLSM + "|AppArmor"
				}
			} else {
				re.LogFeeder.Print("Destroyed AppArmor Enforcer")
			}
		}
	}

	if strings.Contains(re.enforcerType, "selinux") {
		if re.seLinuxEnforcer != nil {
			if err := re.seLinuxEnforcer.DestroySELinuxEnforcer(); err != nil {
				re.LogFeeder.Err(err.Error())

				if errorLSM == "" {
					errorLSM = "SELinux"
				} else {
					errorLSM = errorLSM + "|SELinux"
				}
			} else {
				re.LogFeeder.Print("Destroyed SELinux Enforcer")
			}
		}
	}

	if errorLSM != "" {
		return fmt.Errorf("Failed to destroy RuntimeEnforcer (%s)", errorLSM)
	}

	return nil
}
