package enforcer

import (
	"io/ioutil"
	"os"
	"sync"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

const (
	BaseContainer = `(block container
		(type process)
		(type socket)
		(roletype system_r process)
		(typeattributeset domain (process ))
		(typeattributeset container_domain (process ))
		(typeattributeset svirt_sandbox_domain (process ))
		(typeattributeset file_type (socket ))
		(allow process socket (sock_file (create open getattr setattr read write rename link unlink ioctl lock append)))
		(allow process proc_type (file (getattr open read)))
		(allow process cpu_online_t (file (getattr open read)))
		(allow container_runtime_t process (key (create link read search setattr view write)))
		)

		`

	BaseNetwork = `(block net_container
		(blockinherit container)
		(typeattributeset sandbox_net_domain (process))
	)
	
	(block restricted_net_container
		(blockinherit container)
	
		(allow process process (tcp_socket (ioctl read getattr lock write setattr append bind connect getopt setopt shutdown create listen accept)))
		(allow process process (udp_socket (ioctl read getattr lock write setattr append bind connect getopt setopt shutdown create)))
	
		(allow process proc_t (lnk_file (read)))
	
		(allow process node_t (node (tcp_recv tcp_send recvfrom sendto)))
		(allow process node_t (node (udp_recv recvfrom)))
		(allow process node_t (node (udp_send sendto)))
	
		(allow process node_t (udp_socket (node_bind)))
		(allow process node_t (tcp_socket (node_bind)))
	
		(allow process http_port_t (tcp_socket (name_connect)))
		(allow process http_port_t (tcp_socket (recv_msg send_msg)))
	)

	`
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

const (
	SELinuxDirReadOnly   = "getattr search open read lock ioctl"
	SELinuxDirReadWrite  = "getattr search open read lock ioctl setattr write link add_name remove_name reparent lock create unlink rename rmdir"
	SELinuxFileReadOnly  = "getattr ioctl lock open read"
	SELinuxFileReadWrite = "getattr ioctl lock open read write append lock create rename link unlink"
)

// RegisterSELinuxProfile Function
func (se *SELinuxEnforcer) RegisterSELinuxProfile(pod tp.K8sPod, containerName, profileName string) bool {
	namespace := pod.Metadata["namespaceName"]
	podName := pod.Metadata["podName"]

	selinuxVolumeDefault := "(block " + profileName + "\n" +
		"	(blockinherit container)\n" +
		"	(blockinherit restricted_net_container)\n" +
		"	(allow process process (capability (dac_override)))\n"

	for _, hostVolume := range pod.HostVolumes {
		if readOnly, ok := hostVolume.UsedByContainer[containerName]; ok {
			if context, err := kl.GetSELinuxType(hostVolume.PathName); err != nil {
				se.LogFeeder.Err(err.Error())
				return false
			} else {
				contextLine := "	(allow process " + context

				if readOnly {
					contextDirLine := contextLine + " (dir (" + SELinuxDirReadOnly + ")))\n"
					contextFileLine := contextLine + " (file (" + SELinuxFileReadOnly + ")))\n"
					selinuxVolumeDefault = selinuxVolumeDefault + contextDirLine + contextFileLine
				} else {
					contextDirLine := contextLine + " (dir (" + SELinuxDirReadWrite + ")))\n"
					contextFileLine := contextLine + " (file (" + SELinuxFileReadWrite + ")))\n"
					selinuxVolumeDefault = selinuxVolumeDefault + contextDirLine + contextFileLine
				}
			}
		}
	}

	selinuxVolumeDefault = selinuxVolumeDefault + ")\n"

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

	if _, err := newFile.WriteString(selinuxVolumeDefault); err != nil {
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
func (se *SELinuxEnforcer) UnregisterSELinuxProfile(pod tp.K8sPod, containerName, profileName string) bool {
	namespace := pod.Metadata["namespaceName"]
	podName := pod.Metadata["podName"]

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
