package types

import (
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============ //
// == Docker == //
// ============ //

// Container Structure
type Container struct {
	ContainerID   string `json:"containerID"`
	ContainerName string `json:"containerName"`

	Status string `json:"status"`

	HostName string `json:"hostName"`
	HostIP   string `json:"hostIP"`

	NamespaceName      string `json:"namespaceName"`
	ContainerGroupName string `json:"containerGroupName"`

	ImageID   string `json:"imageID"`
	ImageName string `json:"imageName"`

	Labels []string `json:"labels"`

	AppArmorProfile string `json:"apparmorProfile"`
}

// ContainerGroup Structure
type ContainerGroup struct {
	NamespaceName      string `json:"namespaceName"`
	ContainerGroupName string `json:"containerGroupName"`

	Labels     []string `json:"labels"`
	Identities []string `json:"identities"`

	Containers []string `json:"containers"`

	SecurityPolicies []SecurityPolicy  `json:"securityPolicies"`
	AppArmorProfiles map[string]string `json:"apparmorProfiles"`
}

// ================ //
// == Kubernetes == //
// ================ //

// K8sPod Structure
type K8sPod struct {
	Metadata    map[string]string
	Annotations map[string]string
	Labels      map[string]string
}

// K8sPodEvent Structure
type K8sPodEvent struct {
	Type   string `json:"type"`
	Object v1.Pod `json:"object"`
}

// K8sKubeArmorPolicyEvent Structure
type K8sKubeArmorPolicyEvent struct {
	Type   string             `json:"type"`
	Object K8sKubeArmorPolicy `json:"object"`
}

// K8sKubeArmorPolicy Structure
type K8sKubeArmorPolicy struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     SecuritySpec      `json:"spec"`
}

// K8sSystemPolicies Structure
type K8sKubeArmorPolicies struct {
	Items []K8sKubeArmorPolicy `json:"items"`
}

// ============= //
// == Logging == //
// ============= //

// Message Structure
type Message struct {
	Source   string `json:"source"`
	SourceIP string `json:"sourceIP"`

	Level   string `json:"level"`
	Message string `json:"message"`

	UpdatedTime string `json:"updatedTime"`
}

// SystemLog Structure
type SystemLog struct {
	// updated time
	UpdatedTime string `json:"updatedTime"`

	// host
	HostName string `json:"hostName"`

	// container
	ContainerID   string `json:"containerID"`
	ContainerName string `json:"containerName"`

	// common
	HostPID int    `json:"hostPid"`
	PPID    int    `json:"ppid"`
	PID     int    `json:"pid"`
	TID     int    `json:"tid"`
	UID     int    `json:"uid"`
	Comm    string `json:"comm"`

	// syscall
	Syscall string `json:"syscall"`
	Argnum  int    `json:"argnum"`
	Retval  int    `json:"retval"`

	// data
	Data string `json:"data"`
}

// AuditLog Structure
type AuditLog struct {
	// updated time
	UpdatedTime string `json:"updatedTime"`

	// host
	HostName string `json:"hostName"`

	// container
	ContainerID   string `json:"containerID"`
	ContainerName string `json:"containerName"`

	// audit
	HostPID   int    `json:"hostPid"`
	Source    string `json:"source"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`

	// raw
	Raw string `json:"rawdata,omitempty"`
}

// ===================== //
// == Security Policy == //
// ===================== //

// SelectorType Structure
type SelectorType struct {
	MatchNames  map[string]string `json:"matchNames,omitempty"`
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	Identities []string `json:"identities,omitempty"` // set during policy update
}

// MatchSourceType Structure
type MatchSourceType struct {
	Path      string `json:"path,omitempty"`
	Directory string `json:"dir,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
}

// ProcessPathType Structure
type ProcessPathType struct {
	Path       string            `json:"path"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`
}

// ProcessDirectoryType Structure
type ProcessDirectoryType struct {
	Directory  string            `json:"dir"`
	Recursive  bool              `json:"recursive,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`
}

// ProcessPatternType Structure
type ProcessPatternType struct {
	Pattern    string            `json:"pattern"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`
}

// ProcessType Structure
type ProcessType struct {
	MatchPaths       []ProcessPathType      `json:"matchPaths,omitempty"`
	MatchDirectories []ProcessDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []ProcessPatternType   `json:"matchPatterns,omitempty"`
}

// FilePathType Structure
type FilePathType struct {
	Path       string            `json:"path"`
	ReadOnly   bool              `json:"readOnly,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`
}

// FileDirectoryType Structure
type FileDirectoryType struct {
	Directory  string            `json:"dir"`
	ReadOnly   bool              `json:"readOnly,omitempty"`
	Recursive  bool              `json:"recursive,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`
}

// FilePatternType Structure
type FilePatternType struct {
	Pattern    string            `json:"pattern"`
	ReadOnly   bool              `json:"readOnly,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`
}

// FileType Structure
type FileType struct {
	MatchPaths       []FilePathType      `json:"matchPaths,omitempty"`
	MatchDirectories []FileDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []FilePatternType   `json:"matchPatterns,omitempty"`
}

// NetworkProtocolType Structure
type NetworkProtocolType struct {
	Protocol string `json:"protocol"`
	IPv4     bool   `json:"ipv4,omitempty"`
	IPv6     bool   `json:"ipv6,omitempty"`
}

// NetworkProcFileType Structure
type NetworkProcFileType struct {
	MatchPaths []string `json:"matchPaths,omitempty"`
	MatchNames []string `json:"matchNames,omitempty"`
}

// NetworkPolicy Structure
type NetworkPolicy struct {
	Process NetworkProcFileType `json:"process,omitempty"`
	File    NetworkProcFileType `json:"file,omitempty"`

	PolicyType   int    `json:"policyType,omitempty"`   // set by container monitor
	PolicyAction string `json:"policyAction,omitempty"` // set by container monitor
}

// NetworkType Structure
type NetworkType struct {
	MatchProtocols []NetworkProtocolType `json:"matchProtocols,omitempty"`
	MatchSources   []NetworkPolicy       `json:"matchSources,omitempty"`
}

// CapabilitiesType Structure
type CapabilitiesType struct {
	MatchCapabilities []string `json:"matchCapabilities,omitempty"`
	MatchOperations   []string `json:"matchOperations,omitempty"`
}

// SecuritySpec Structure
type SecuritySpec struct {
	Selector SelectorType `json:"selector"`

	Process      ProcessType      `json:"process,omitempty"`
	File         FileType         `json:"file,omitempty"`
	Network      NetworkType      `json:"network,omitempty"`
	Capabilities CapabilitiesType `json:"capabilities,omitempty"`

	Action string `json:"action"`
}

// SecurityPolicy Structure
type SecurityPolicy struct {
	Metadata map[string]string `json:"metadata"`
	Spec     SecuritySpec      `json:"spec"`
}

// ================== //
// == Process Tree == //
// ================== //

// PidMap for host pid -> process node
type PidMap map[uint32]PidNode

// PidNode Structure
type PidNode struct {
	Policy NetworkPolicy

	PidID uint32
	MntID uint32

	HostPID uint32
	PPID    uint32
	PID     uint32
	TID     uint32

	Comm     string
	ExecPath string

	EventID   uint32
	Monitored bool

	Exited     bool
	ExitedTime time.Time
}
