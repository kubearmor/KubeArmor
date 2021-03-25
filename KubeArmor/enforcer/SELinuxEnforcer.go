package enforcer

import (
	"io/ioutil"
	"os"
	"sync"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ====================== //
// == SELinux Enforcer == //
// ====================== //

const (
	selinuxContextTemplates = "/usr/share/templates/"
)

// SELinuxEnforcer Structure
type SELinuxEnforcer struct {
	// logs
	LogFeeder *fd.Feeder

	SELinuxProfiles     map[string]int
	SELinuxProfilesLock *sync.Mutex
}

// NewSELinuxEnforcer Function
func NewSELinuxEnforcer(feeder *fd.Feeder) *SELinuxEnforcer {
	se := &SELinuxEnforcer{}

	se.LogFeeder = feeder

	se.SELinuxProfiles = map[string]int{}
	se.SELinuxProfilesLock = &sync.Mutex{}

	return se
}

// DestroySELinuxEnforcer Function
func (se *SELinuxEnforcer) DestroySELinuxEnforcer() error {
	return nil
}

// ================================ //
// == SELinux Profile Management == //
// ================================ //

// RegisterSELinuxProfile Function
func (se *SELinuxEnforcer) RegisterSELinuxProfile(namespace, podName, profileName string) bool {
	selinuxDefault := "(block " + profileName + "\n" +
		"	(blockinherit container)\n" +
		"	(blockinherit restricted_net_container)\n" +
		")\n"

	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	profilePath := selinuxContextTemplates + profileName + ".cil"

	if _, err := os.Stat(profilePath); err == nil {
		if err := os.Remove(profilePath); err != nil {
			se.LogFeeder.Err(err.Error())
			return false
		}
	}

	newFile, err := os.Create(profilePath)
	if err != nil {
		se.LogFeeder.Err(err.Error())
		return false
	}

	if _, err := newFile.WriteString(selinuxDefault); err != nil {
		se.LogFeeder.Err(err.Error())
		return false
	}
	newFile.Close()

	if _, err := kl.GetCommandOutputWithErr("semanage", []string{"module", "-a", profilePath}); err == nil {
		if _, ok := se.SELinuxProfiles[profileName]; !ok {
			se.SELinuxProfiles[profileName] = 1
			se.LogFeeder.Printf("Registered a SELinux profile (%s) for (%s/%s)", profileName, namespace, podName)
		}
	} else {
		se.LogFeeder.Printf("Failed to register a SELinux profile (%s) for (%s/%s): %s", profileName, namespace, podName, err.Error())
		return false
	}

	return false
}

// UnregisterSELinuxProfile Function
func (se *SELinuxEnforcer) UnregisterSELinuxProfile(namespace, podName, profileName string) bool {
	se.SELinuxProfilesLock.Lock()
	defer se.SELinuxProfilesLock.Unlock()

	profilePath := selinuxContextTemplates + profileName + ".cil"

	if _, err := os.Stat(profilePath); err == nil {
		_, err := ioutil.ReadFile(profilePath)
		if err != nil {
			se.LogFeeder.Printf("Unabale to unregister a SELinux profile (%s) for (%s/%s): %s", profileName, namespace, podName, err.Error())
			return false
		}
	} else { // not exist
		if err != nil {
			se.LogFeeder.Printf("Unabale to unregister a SELinux profile (%s) for (%s/%s): %s", profileName, namespace, podName, err.Error())
			return false
		}
	}

	if referenceCount, ok := se.SELinuxProfiles[profileName]; ok {
		if referenceCount > 1 {
			se.SELinuxProfiles[profileName]--
			se.LogFeeder.Printf("Decreased the refCount (%d -> %d) of a SELinux profile (%s)", se.SELinuxProfiles[profileName]+1, se.SELinuxProfiles[profileName], profileName)
		} else {
			if _, err := kl.GetCommandOutputWithErr("semanage", []string{"module", "-r", profileName}); err != nil {
				se.LogFeeder.Printf("Failed to unregister a SELinux profile (%s) for (%s/%s): %s", profileName, namespace, podName, err.Error())
				return false
			}

			if err := os.Remove(profilePath); err != nil {
				se.LogFeeder.Err(err.Error())
				return false
			}

			delete(se.SELinuxProfiles, profileName)
			se.LogFeeder.Printf("Unregistered a SELinux profile (%s) for (%s/%s)", profileName, namespace, podName)
		}
	} else {
		se.LogFeeder.Printf("Failed to unregister an unknown SELinux profile (%s) for (%s/%s): not exist profile in the enforecer", profileName, namespace, podName)
		return false
	}

	return true
}

// UpdateSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	//
}

// UpdateHostSecurityPolicies Function
func (se *SELinuxEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	//
}
