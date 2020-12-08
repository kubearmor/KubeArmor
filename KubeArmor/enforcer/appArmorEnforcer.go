package enforcer

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"sync"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ======================= //
// == AppArmor Enforcer == //
// ======================= //

// AppArmorEnforcer Structure
type AppArmorEnforcer struct {
	HomeDir string

	RegisteredAppArmorProfiles     map[string]int
	RegisteredAppArmorProfilesLock *sync.Mutex
}

// NewAppArmorEnforcer Function
func NewAppArmorEnforcer(homeDir string) *AppArmorEnforcer {
	ae := &AppArmorEnforcer{}

	ae.HomeDir = homeDir

	ae.RegisteredAppArmorProfiles = map[string]int{}
	ae.RegisteredAppArmorProfilesLock = &sync.Mutex{}

	// mount securityfs
	kl.GetCommandWithoutOutput("/bin/mount", []string{"-t", "securityfs", "securityfs", "/sys/kernel/security"})

	// reset apparmor profiles
	kl.GetCommandWithoutOutput(homeDir+"/AppArmor/reset_profiles.sh", []string{})

	return ae
}

// DestroyAppArmorEnforcer Function
func (ae *AppArmorEnforcer) DestroyAppArmorEnforcer() {
	for profileName := range ae.RegisteredAppArmorProfiles {
		ae.UnregisterAppArmorProfile(profileName)
	}
}

// ================================= //
// == AppArmor Profile Management == //
// ================================= //

// RegisterAppArmorProfile Function
func (ae *AppArmorEnforcer) RegisterAppArmorProfile(profileName string) {
	if _, err := os.Stat("/etc/apparmor.d/" + profileName); err == nil {
		content, err := ioutil.ReadFile("/etc/apparmor.d/" + profileName)
		if err != nil {
			kg.Printf("Unabale to register an AppArmor profile (%s) (out-of-control)", profileName)
			return
		}

		if !strings.Contains(string(content), "KubeArmor") {
			kg.Printf("Unabale to register an AppArmor profile (%s) (out-of-control)", profileName)
			return
		}
	}

	if err := exec.Command(ae.HomeDir+"/AppArmor/create_profile.sh", profileName).Run(); err == nil {
		if _, ok := ae.RegisteredAppArmorProfiles[profileName]; !ok {
			ae.RegisteredAppArmorProfiles[profileName] = 1
			kg.Printf("Registered an AppArmor profile (%s)", profileName)
		} else {
			ae.RegisteredAppArmorProfiles[profileName]++
			kg.Printf("Increased the refCount (%d -> %d) of an AppArmor profile (%s)", ae.RegisteredAppArmorProfiles[profileName]-1, ae.RegisteredAppArmorProfiles[profileName], profileName)
		}
	} else {
		kg.Printf("Failed to register an AppArmor profile (%s)", profileName)
	}
}

// UnregisterAppArmorProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorProfile(profileName string) {
	if _, err := os.Stat("/etc/apparmor.d/" + profileName); err == nil {
		content, err := ioutil.ReadFile("/etc/apparmor.d/" + profileName)
		if err != nil {
			kg.Printf("Unabale to unregister an AppArmor profile (%s) (out-of-control)", profileName)
			return
		}

		if !strings.Contains(string(content), "KubeArmor") {
			kg.Printf("Unabale to unregister an AppArmor profile (%s) (out-of-control)", profileName)
			return
		}
	}

	if referenceCount, ok := ae.RegisteredAppArmorProfiles[profileName]; ok {
		if referenceCount > 1 {
			ae.RegisteredAppArmorProfiles[profileName]--
			kg.Printf("Decreased the refCount (%d -> %d) of an AppArmor profile (%s)", ae.RegisteredAppArmorProfiles[profileName]+1, ae.RegisteredAppArmorProfiles[profileName], profileName)
		} else {
			if err := exec.Command(ae.HomeDir+"/AppArmor/delete_profile.sh", profileName).Run(); err == nil {
				delete(ae.RegisteredAppArmorProfiles, profileName)
				kg.Printf("Unregistered an AppArmor profile (%s)", profileName)
			} else {
				kg.Printf("Failed to unregister an AppArmor profile (%s)", profileName)
			}
		}
	} else {
		kg.Printf("Failed to unregister an unknown AppArmor profile (%s)", profileName)
	}
}

// ================================= //
// == Security Policy Enforcement == //
// ================================= //

// UpdateAppArmorProfile Function
func UpdateAppArmorProfile(conGroup tp.ContainerGroup, appArmorProfile string, securityPolicies []tp.SecurityPolicy) {
	if policyCount, newProfile, ok := GenerateAppArmorProfile(appArmorProfile, securityPolicies); ok {
		newfile, _ := os.Create("/etc/apparmor.d/" + appArmorProfile)
		defer newfile.Close()

		if _, err := newfile.WriteString(newProfile); err != nil {
			kg.Err(err.Error())
			return
		}

		if err := newfile.Sync(); err != nil {
			kg.Err(err.Error())
			return
		}

		if err := exec.Command("/sbin/apparmor_parser", "-r", "-W", "/etc/apparmor.d/"+appArmorProfile).Run(); err == nil {
			kg.Printf("Updated %d security policies to %s/%s/%s", policyCount, conGroup.NamespaceName, conGroup.ContainerGroupName, appArmorProfile)
		} else {
			kg.Printf("Failed to update %d security policies to %s/%s/%s", policyCount, conGroup.NamespaceName, conGroup.ContainerGroupName, appArmorProfile)
		}
	}
}

// UpdateSecurityPolicies Function
func (ae *AppArmorEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	appArmorProfiles := []string{}

	for _, containerName := range conGroup.Containers {
		if kl.ContainsElement([]string{"docker-default", "unconfined"}, conGroup.AppArmorProfiles[containerName]) {
			continue
		} else if conGroup.AppArmorProfiles[containerName] == "" { // unconfined in k8s
			continue
		}

		if !kl.ContainsElement(appArmorProfiles, conGroup.AppArmorProfiles[containerName]) {
			appArmorProfiles = append(appArmorProfiles, conGroup.AppArmorProfiles[containerName])
		}
	}

	for _, appArmorProfile := range appArmorProfiles {
		UpdateAppArmorProfile(conGroup, appArmorProfile, conGroup.SecurityPolicies)
	}
}
