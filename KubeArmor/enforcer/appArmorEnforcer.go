package enforcer

import (
	"io/ioutil"
	"os"
	"strings"
	"sync"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ======================= //
// == AppArmor Enforcer == //
// ======================= //

// AppArmorEnforcer Structure
type AppArmorEnforcer struct {
	// logs
	LogFeeder *fd.Feeder

	// host name
	HostName string

	// host security
	EnableHostPolicy bool
	HostProfile      string

	// container security
	AppArmorProfiles     map[string]int
	AppArmorProfilesLock *sync.Mutex
}

// NewAppArmorEnforcer Function
func NewAppArmorEnforcer(feeder *fd.Feeder, enableHostPolicy bool) *AppArmorEnforcer {
	ae := &AppArmorEnforcer{}

	ae.LogFeeder = feeder

	ae.HostName = kl.GetHostName()

	ae.EnableHostPolicy = enableHostPolicy
	ae.HostProfile = ""

	ae.AppArmorProfiles = map[string]int{}
	ae.AppArmorProfilesLock = &sync.Mutex{}

	existingProfiles := []string{}

	if output, err := kl.GetCommandOutputWithErr("aa-status", []string{}); err != nil {
		ae.LogFeeder.Errf("Failed to get the list of AppArmor profiles (%s)", err.Error())
		return nil
	} else {
		for _, line := range strings.Split(string(output), "\n") {
			// the line should be something like "   /path (pid) profile"
			if !strings.HasPrefix(line, "   ") {
				continue
			}

			// check if there are KubeArmor's profiles used by containers
			if words := strings.Split(line, " "); len(words) == 6 {
				if !kl.ContainsElement(existingProfiles, words[5]) {
					existingProfiles = append(existingProfiles, words[5])
				}
			}
		}
	}

	files, err := ioutil.ReadDir("/etc/apparmor.d")
	if err != nil {
		ae.LogFeeder.Errf("Failed to read /etc/apparmor.d (%s)", err.Error())
		return nil
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		fileName := file.Name()

		data, err := ioutil.ReadFile("/etc/apparmor.d/" + fileName)
		if err != nil {
			ae.LogFeeder.Errf("Failed to read /etc/apparmor.d/%s (%s)", fileName, err.Error())
			continue
		}

		str := string(data)

		if strings.Contains(str, "KubeArmor") {
			if kl.ContainsElement(existingProfiles, fileName) {
				continue // if the profile is used by a running container, do not remove it
			}

			if _, err := kl.GetCommandOutputWithErr("apparmor_parser", []string{"-R", "/etc/apparmor.d/" + fileName}); err != nil {
				ae.LogFeeder.Errf("Failed to detach /etc/apparmor.d/%s (%s)", fileName, err.Error())
				continue // still need to check other profiles
			}

			if err := os.Remove("/etc/apparmor.d/" + fileName); err != nil {
				ae.LogFeeder.Errf("Failed to remove /etc/apparmor.d/%s (%s)", fileName, err.Error())
				continue // still need to check other profiles
			}

			ae.LogFeeder.Printf("Removed an inactive AppArmor profile (%s)", fileName)
		}
	}

	if ae.EnableHostPolicy {
		if ok := ae.RegisterAppArmorHostProfile(); !ok {
			return nil
		}
	}

	return ae
}

// DestroyAppArmorEnforcer Function
func (ae *AppArmorEnforcer) DestroyAppArmorEnforcer() error {
	if ae.EnableHostPolicy {
		ae.UnregisterAppArmorHostProfile()
	}

	return nil
}

// ================================= //
// == AppArmor Profile Management == //
// ================================= //

// RegisterAppArmorProfile Function
func (ae *AppArmorEnforcer) RegisterAppArmorProfile(profileName string) bool {
	apparmorDefault := "## == Managed by KubeArmor == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile apparmor-default flags=(attach_disconnected,mediate_deleted) {\n" +
		"  ## == PRE START == ##\n" +
		"  #include <abstractions/base>\n" +
		"  umount,\n" +
		"  file,\n" +
		"  network,\n" +
		"  capability,\n" +
		"  ## == PRE END == ##\n" +
		"\n" +
		"  ## == POLICY START == ##\n" +
		"  ## == POLICY END == ##\n" +
		"\n" +
		"  ## == POST START == ##\n" +
		"  /lib/x86_64-linux-gnu/{*,**} r,\n" +
		"\n" +
		"  deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,\n" +
		"  deny @{PROC}/sysrq-trigger rwklx,\n" +
		"  deny @{PROC}/mem rwklx,\n" +
		"  deny @{PROC}/kmem rwklx,\n" +
		"  deny @{PROC}/kcore rwklx,\n" +
		"\n" +
		"  deny mount,\n" +
		"\n" +
		"  deny /sys/[^f]*/** wklx,\n" +
		"  deny /sys/f[^s]*/** wklx,\n" +
		"  deny /sys/fs/[^c]*/** wklx,\n" +
		"  deny /sys/fs/c[^g]*/** wklx,\n" +
		"  deny /sys/fs/cg[^r]*/** wklx,\n" +
		"  deny /sys/firmware/efi/efivars/** rwklx,\n" +
		"  deny /sys/kernel/security/** rwklx,\n" +
		"  ## == POST END == ##\n" +
		"}\n"

	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

	if _, err := os.Stat("/etc/apparmor.d/" + profileName); err == nil {
		content, err := ioutil.ReadFile("/etc/apparmor.d/" + profileName)
		if err != nil {
			ae.LogFeeder.Printf("Unabale to register an AppArmor profile (%s, %s)", profileName, err.Error())
			return false
		}

		if !strings.Contains(string(content), "KubeArmor") {
			ae.LogFeeder.Printf("Unabale to register an AppArmor profile (%s) (out-of-control)", profileName)
			return false
		}
	} else {
		newProfile := strings.Replace(apparmorDefault, "apparmor-default", profileName, -1)

		newFile, err := os.Create("/etc/apparmor.d/" + profileName)
		if err != nil {
			ae.LogFeeder.Err(err.Error())
			return false
		}
		defer newFile.Close()

		if _, err := newFile.WriteString(newProfile); err != nil {
			ae.LogFeeder.Err(err.Error())
			return false
		}
	}

	if output, err := kl.GetCommandOutputWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + profileName}); err == nil {
		if _, ok := ae.AppArmorProfiles[profileName]; !ok {
			ae.AppArmorProfiles[profileName] = 1
			ae.LogFeeder.Printf("Registered an AppArmor profile (%s)", profileName)
		} else {
			ae.AppArmorProfiles[profileName]++
			ae.LogFeeder.Printf("Increased the refCount (%d -> %d) of an AppArmor profile (%s)", ae.AppArmorProfiles[profileName]-1, ae.AppArmorProfiles[profileName], profileName)
		}
	} else {
		ae.LogFeeder.Printf("Failed to register an AppArmor profile (%s, %s, %s)", profileName, output, err.Error())
		return false
	}

	return true
}

// UnregisterAppArmorProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorProfile(profileName string) bool {
	ae.AppArmorProfilesLock.Lock()
	defer ae.AppArmorProfilesLock.Unlock()

	if _, err := os.Stat("/etc/apparmor.d/" + profileName); err == nil {
		content, err := ioutil.ReadFile("/etc/apparmor.d/" + profileName)
		if err != nil {
			ae.LogFeeder.Printf("Unabale to unregister an AppArmor profile (%s, %s)", profileName, err.Error())
			return false
		}

		if !strings.Contains(string(content), "KubeArmor") {
			ae.LogFeeder.Printf("Unabale to unregister an AppArmor profile (%s) (out-of-control)", profileName)
			return false
		}
	}

	if referenceCount, ok := ae.AppArmorProfiles[profileName]; ok {
		if referenceCount > 1 {
			ae.AppArmorProfiles[profileName]--
			ae.LogFeeder.Printf("Decreased the refCount (%d -> %d) of an AppArmor profile (%s)", ae.AppArmorProfiles[profileName]+1, ae.AppArmorProfiles[profileName], profileName)
		} else {
			if _, err := kl.GetCommandOutputWithErr("apparmor_parser", []string{"-R", "/etc/apparmor.d/" + profileName}); err != nil {
				ae.LogFeeder.Printf("Failed to unregister an AppArmor profile (%s, %s)", profileName, err.Error())
				return false
			}

			if err := os.Remove("/etc/apparmor.d/" + profileName); err != nil {
				ae.LogFeeder.Err(err.Error())
				return false
			}

			delete(ae.AppArmorProfiles, profileName)
			ae.LogFeeder.Printf("Unregistered an AppArmor profile (%s)", profileName)
		}
	} else {
		ae.LogFeeder.Printf("Failed to unregister an unknown AppArmor profile (%s)", profileName)
		return false
	}

	return true
}

// ====================================== //
// == AppArmor Host Profile Management == //
// ====================================== //

func (ae *AppArmorEnforcer) CreateAppArmorHostProfile() error {
	apparmorHostDefault := "## == Managed by KubeArmor == ##\n" +
		"\n" +
		"#include <tunables/global>\n" +
		"\n" +
		"profile kubearmor.host /** flags=(attach_disconnected,mediate_deleted) {\n" +
		"  #include <abstractions/base>\n" +
		"\n" +
		"  file,\n" +
		"  mount,\n" +
		"  umount,\n" +
		"  ptrace,\n" +
		"  network,\n" +
		"  capability,\n" +
		"\n" +
		"  /usr/bin/runc Ux,\n" +
		"\n" +
		"  ## == POLICY START == ##\n" +
		"  ## == POLICY END == ##\n" +
		"}\n"

	newfile, err := os.Create("/tmp/kubearmor.host")
	if err != nil {
		ae.LogFeeder.Err(err.Error())
		return err
	}
	defer newfile.Close()

	if _, err := newfile.WriteString(apparmorHostDefault); err != nil {
		ae.LogFeeder.Err(err.Error())
		return err
	}

	if err := newfile.Sync(); err != nil {
		ae.LogFeeder.Err(err.Error())
		return err
	}

	ae.HostProfile = apparmorHostDefault

	return nil
}

func (ae *AppArmorEnforcer) RemoveAppArmorHostProfile() error {
	if _, err := os.Stat("/tmp/kubearmor.host"); err != nil {
		return nil
	}

	if err := os.Remove("/tmp/kubearmor.host"); err != nil {
		ae.LogFeeder.Errf("Failed to remove the AppArmor host profile in %s (%s)", ae.HostName, err.Error())
		return err
	}

	return nil
}

// RegisterAppArmorHostProfile Function
func (ae *AppArmorEnforcer) RegisterAppArmorHostProfile() bool {
	if err := ae.CreateAppArmorHostProfile(); err != nil {
		ae.LogFeeder.Errf("Failed to create the AppArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	if output, err := kl.GetCommandOutputWithErr("apparmor_parser", []string{"-r", "-W", "-C", "/tmp/kubearmor.host"}); err == nil {
		ae.LogFeeder.Printf("Registered an AppArmor host profile in %s", ae.HostName)
	} else {
		ae.LogFeeder.Printf("Failed to registered an AppArmor host profile in %s (%s)", ae.HostName, output)
	}

	if err := ae.RemoveAppArmorHostProfile(); err != nil {
		ae.LogFeeder.Errf("Failed to remove the AppArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	return true
}

// UnregisterAppArmorHostProfile Function
func (ae *AppArmorEnforcer) UnregisterAppArmorHostProfile() bool {
	if err := ae.CreateAppArmorHostProfile(); err != nil {
		ae.LogFeeder.Errf("Failed to create the AppArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	if output, err := kl.GetCommandOutputWithErr("apparmor_parser", []string{"-R", "/tmp/kubearmor.host"}); err == nil {
		ae.LogFeeder.Printf("Unegistered an AppArmor host profile in %s", ae.HostName)
	} else {
		ae.LogFeeder.Printf("Failed to unregister the AppArmor host profile (%s, %s)", output, err.Error())
	}

	if err := ae.RemoveAppArmorHostProfile(); err != nil {
		ae.LogFeeder.Errf("Failed to remove the AppArmor host profile in %s (%s)", ae.HostName, err.Error())
		return false
	}

	return true
}

// ================================= //
// == Security Policy Enforcement == //
// ================================= //

// UpdateAppArmorProfile Function
func (ae *AppArmorEnforcer) UpdateAppArmorProfile(conGroup tp.ContainerGroup, appArmorProfile string, securityPolicies []tp.SecurityPolicy) {
	if policyCount, newProfile, ok := ae.GenerateAppArmorProfile(appArmorProfile, securityPolicies); ok {
		newfile, err := os.Create("/etc/apparmor.d/" + appArmorProfile)
		if err != nil {
			ae.LogFeeder.Err(err.Error())
			return
		}
		defer newfile.Close()

		if _, err := newfile.WriteString(newProfile); err != nil {
			ae.LogFeeder.Err(err.Error())
			return
		}

		if err := newfile.Sync(); err != nil {
			ae.LogFeeder.Err(err.Error())
			return
		}

		if output, err := kl.GetCommandOutputWithErr("apparmor_parser", []string{"-r", "-W", "/etc/apparmor.d/" + appArmorProfile}); err == nil {
			ae.LogFeeder.Printf("Updated %d security rules to %s/%s/%s", policyCount, conGroup.NamespaceName, conGroup.ContainerGroupName, appArmorProfile)
		} else {
			ae.LogFeeder.Printf("Failed to update %d security rules to %s/%s/%s (%s)", policyCount, conGroup.NamespaceName, conGroup.ContainerGroupName, appArmorProfile, output)
		}
	}
}

// UpdateSecurityPolicies Function
func (ae *AppArmorEnforcer) UpdateSecurityPolicies(conGroup tp.ContainerGroup) {
	appArmorProfiles := []string{}

	for _, containerName := range conGroup.Containers {
		if kl.ContainsElement([]string{"docker-default", "unconfined", ""}, conGroup.AppArmorProfiles[containerName]) {
			continue
		}

		if !kl.ContainsElement(appArmorProfiles, conGroup.AppArmorProfiles[containerName]) {
			appArmorProfiles = append(appArmorProfiles, conGroup.AppArmorProfiles[containerName])
		}
	}

	for _, appArmorProfile := range appArmorProfiles {
		ae.UpdateAppArmorProfile(conGroup, appArmorProfile, conGroup.SecurityPolicies)
	}
}

// ====================================== //
// == Host Security Policy Enforcement == //
// ====================================== //

// UpdateAppArmorHostProfile Function
func (ae *AppArmorEnforcer) UpdateAppArmorHostProfile(secPolicies []tp.HostSecurityPolicy) {
	if policyCount, newProfile, ok := ae.GenerateAppArmorHostProfile(secPolicies); ok {
		newfile, err := os.Create("/tmp/kubearmor.host")
		if err != nil {
			ae.LogFeeder.Err(err.Error())
			return
		}
		defer newfile.Close()

		if _, err := newfile.WriteString(newProfile); err != nil {
			ae.LogFeeder.Err(err.Error())
			return
		}

		if err := newfile.Sync(); err != nil {
			ae.LogFeeder.Err(err.Error())
			return
		}

		if output, err := kl.GetCommandOutputWithErr("apparmor_parser", []string{"-r", "-W", "/tmp/kubearmor.host"}); err == nil {
			ae.LogFeeder.Printf("Updated %d host security rules to the AppArmor host profile in %s", policyCount, ae.HostName)
		} else {
			ae.LogFeeder.Printf("Failed to update %d host security rules to the AppArmor host profile in %s (%s)", policyCount, ae.HostName, output)
		}

		if err := ae.RemoveAppArmorHostProfile(); err != nil {
			ae.LogFeeder.Errf("Failed to remove the AppArmor host profile in %s (%s)", ae.HostName, err.Error())
			return
		}
	}
}

// UpdateHostSecurityPolicies Function
func (ae *AppArmorEnforcer) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	if !ae.EnableHostPolicy {
		return
	}

	ae.UpdateAppArmorHostProfile(secPolicies)
}
