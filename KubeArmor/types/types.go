// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package types is an extension of the CRD types.
package types

import (
	"regexp"
	"time"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============ //
// == Docker == //
// ============ //

// Container Structure
type Container struct {
	ContainerID    string `json:"containerID"`
	ContainerName  string `json:"containerName"`
	ContainerImage string `json:"containerImage"`

	NamespaceName string   `json:"namespaceName"`
	Owner         PodOwner `json:"owner,omitempty"`
	EndPointName  string   `json:"endPointName"`
	Labels        string   `json:"labels"`

	AppArmorProfile string `json:"apparmorProfile"`
	Privileged      bool   `json:"privileged"`

	// == //

	PidNS uint32 `json:"pidns"`
	MntNS uint32 `json:"mntns"`
	Pid   uint32 `json:"pid"`

	// == //

	NodeName      string `json:"node_name"`
	ProtocolPort  string `json:"protocolPort"`
	Status        string `json:"status"`
	ContainerIP   string `json:"container_ip"`
	LastUpdatedAt string `json:"last_updated_at"`

	// == //

	PolicyEnabled int `json:"policyEnabled"`

	ProcessVisibilityEnabled      bool `json:"processVisibilityEnabled"`
	FileVisibilityEnabled         bool `json:"fileVisibilityEnabled"`
	NetworkVisibilityEnabled      bool `json:"networkVisibilityEnabled"`
	CapabilitiesVisibilityEnabled bool `json:"capabilitiesVisibilityEnabled"`
}

// PodOwner struct
type PodOwner struct {
	Ref       string `json:"ref,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// Namespace struct
type Namespace struct {
	Name                    string `json:"name,omitempty"`
	Labels                  string `json:"labels,omitempty"`
	KubearmorFilePosture    string `json:"kubearmor_file_posture,omitempty"`
	KubearmorNetworkPosture string `json:"kubearmor_network_posture,omitempty"`
	LastUpdatedAt           string `json:"last_updated_at,omitempty"`

	ContainerCount int `json:"container_count,omitempty"`
}

// EndPoint Structure
// k8s: Endpoint ~= pod
// non-k8s: Endpoint ~= container
type EndPoint struct {
	NamespaceName string `json:"namespaceName"`

	EndPointName  string `json:"endPointName"`
	ContainerName string `json:"containerName"`

	Labels     map[string]string `json:"labels"`
	Identities []string          `json:"identities"`

	Containers       []string `json:"containers"`
	AppArmorProfiles []string `json:"apparmorProfiles"`
	SELinuxProfiles  []string `json:"selinuxProfiles"`

	SecurityPolicies []SecurityPolicy `json:"securityPolicies"`

	// only needed for unorchestrated containers
	PrivilegedContainers map[string]struct{} `json:"privilegdContainers"`

	// == //

	PolicyEnabled  int            `json:"policyEnabled"`
	DefaultPosture DefaultPosture `json:"defaultPosture"`

	ProcessVisibilityEnabled      bool `json:"processVisibilityEnabled"`
	FileVisibilityEnabled         bool `json:"fileVisibilityEnabled"`
	NetworkVisibilityEnabled      bool `json:"networkVisibilityEnabled"`
	CapabilitiesVisibilityEnabled bool `json:"capabilitiesVisibilityEnabled"`
}

// Node Structure
type Node struct {
	ClusterName string `json:"clusterName"`
	NodeName    string `json:"nodeName"`
	NodeIP      string `json:"nodeIP"`

	Annotations map[string]string `json:"annotations"`
	Labels      map[string]string `json:"labels"`

	Identities []string `json:"identities"`

	Architecture    string `json:"architecture"`
	OperatingSystem string `json:"operatingSystem"`
	OSImage         string `json:"osImage"`
	KernelVersion   string `json:"kernelVersion"`
	KubeletVersion  string `json:"kubeletVersion"`

	ContainerRuntimeVersion string `json:"containerRuntimeVersion"`

	// == //

	LastUpdatedAt string `json:"last_updated_at"`

	// == //

	PolicyEnabled int `json:"policyEnabled"`

	ProcessVisibilityEnabled      bool `json:"processVisibilityEnabled"`
	FileVisibilityEnabled         bool `json:"fileVisibilityEnabled"`
	NetworkVisibilityEnabled      bool `json:"networkVisibilityEnabled"`
	CapabilitiesVisibilityEnabled bool `json:"capabilitiesVisibilityEnabled"`
}

// ================ //
// == Kubernetes == //
// ================ //

// K8sNodeEvent Structure
type K8sNodeEvent struct {
	Type   string  `json:"type"`
	Object v1.Node `json:"object"`
}

// K8sPod Structure
type K8sPod struct {
	Metadata        map[string]string
	Annotations     map[string]string
	Labels          map[string]string
	Containers      map[string]string
	ContainerImages map[string]string

	// using two maps here as it is inefficent to
	// obtain either from just one
	// for storing privilegd container names
	PrivilegedContainers map[string]struct{}
	// for storing privileged apparmor profile names
	PrivilegedAppArmorProfiles map[string]struct{}
}

// K8sPodEvent Structure
type K8sPodEvent struct {
	Type   string `json:"type"`
	Object v1.Pod `json:"object"`
}

// K8sPolicyStatus Structure
type K8sPolicyStatus struct {
	Status string `json:"status,omitempty"`
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
	Status   K8sPolicyStatus   `json:"status,omitempty"`
}

// K8sKubeArmorPolicies Structure
type K8sKubeArmorPolicies struct {
	Items []K8sKubeArmorPolicy `json:"items"`
}

// K8sKubeArmorHostPolicyEvent Structure
type K8sKubeArmorHostPolicyEvent struct {
	Type   string                 `json:"type"`
	Object K8sKubeArmorHostPolicy `json:"object"`
}

// K8sKubeArmorHostPolicy Structure
type K8sKubeArmorHostPolicy struct {
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     HostSecuritySpec  `json:"spec"`
	Status   K8sPolicyStatus   `json:"status,omitempty"`
}

// K8sKubeArmorHostPolicies Structure
type K8sKubeArmorHostPolicies struct {
	Items []K8sKubeArmorHostPolicy `json:"items"`
}

// ExecEvent struct
type ExecEvent struct {
	ExecID         string
	ExecutableName string
}

// ============= //
// == Logging == //
// ============= //

// Log Structure
type Log struct {
	// updated time
	Timestamp   int64  `json:"timestamp"`
	UpdatedTime string `json:"updatedTime"`

	// host
	ClusterName string `json:"clusterName,omitempty"`
	HostName    string `json:"hostName"`

	// k8s
	NamespaceName string    `json:"namespaceName,omitempty"`
	Owner         *PodOwner `json:"owner,omitempty"`
	PodName       string    `json:"podName,omitempty"`
	Labels        string    `json:"labels,omitempty"`

	// container
	ContainerID    string `json:"containerID,omitempty"`
	ContainerName  string `json:"containerName,omitempty"`
	ContainerImage string `json:"containerImage,omitempty"`

	// common
	HostPPID int32 `json:"hostPPid"`
	HostPID  int32 `json:"hostPid"`
	PPID     int32 `json:"ppid"`
	PID      int32 `json:"pid"`
	UID      int32 `json:"uid"`

	// exec
	ExecEvent ExecEvent `json:"execEvent"`

	// process
	ParentProcessName string `json:"parentProcessName"`
	ProcessName       string `json:"processName"`

	// enforcer
	Enforcer string `json:"enforcer,omitempty"`

	// policy
	PolicyName string `json:"policyName,omitempty"`

	// severity, tags, message
	Severity string   `json:"severity,omitempty"`
	Tags     string   `json:"tags,omitempty"`
	ATags    []string `json:"atags"`
	Message  string   `json:"message,omitempty"`

	// log
	Type                   string `json:"type"`
	Source                 string `json:"source"`
	Operation              string `json:"operation"`
	Resource               string `json:"resource"`
	Cwd                    string `json:"cwd"`
	TTY                    string `json:"tty,omitempty"`
	OID                    int32  `json:"oid"`
	Data                   string `json:"data,omitempty"`
	Action                 string `json:"action,omitempty"`
	Result                 string `json:"result"`
	MaxAlertsPerSec        int32  `json:"MaxAlertsPerSec,omitempty"`
	DroppingAlertsInterval int32  `json:"DroppingAlertsInterval,omitempty"`
	// == //

	PolicyEnabled int `json:"policyEnabled,omitempty"`

	ProcessVisibilityEnabled      bool `json:"processVisibilityEnabled,omitempty"`
	FileVisibilityEnabled         bool `json:"fileVisibilityEnabled,omitempty"`
	NetworkVisibilityEnabled      bool `json:"networkVisibilityEnabled,omitempty"`
	CapabilitiesVisibilityEnabled bool `json:"capabilitiesVisibilityEnabled,omitempty"`
}

// MatchPolicy Structure
type MatchPolicy struct {
	PolicyName string

	Severity string
	Tags     []string
	Message  string

	Source       string
	Operation    string
	ResourceType string
	Resource     string

	IsFromSource bool
	OwnerOnly    bool
	ReadOnly     bool
	Recursive    bool

	Regexp *regexp.Regexp
	Native bool

	Action string
}

// MatchPolicies Structure
type MatchPolicies struct {
	Policies []MatchPolicy
}

// ===================== //
// == Security Policy == //
// ===================== //

// KubeArmorPolicy Flags
const (
	KubeArmorPolicyDisabled = 0
	KubeArmorPolicyEnabled  = 1
	KubeArmorPolicyAudited  = 2
)

// MatchExpressionType Structure
type MatchExpressionType struct {
	Key      string   `json:"key,omitempty"`
	Operator string   `json:"operator,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// SelectorType Structure
type SelectorType struct {
	// for KubeArmorPolicy
	MatchLabels      map[string]string     `json:"matchLabels,omitempty"`
	MatchExpressions []MatchExpressionType `json:"matchExpressions,omitempty"`

	Containers []string `json:"containers,omitempty"`

	// only for ksp
	Identities []string `json:"identities,omitempty"` // set during policy update

	// for ksp & csp - used in matchExpression, key: label
	MatchExpIdentities []string `json:"matchExpIdentities,omitempty"`
	NonIdentities      []string `json:"nonIdentities,omitempty"`

	// only for csp
	NamespaceList []string `json:"namespaceList,omitempty"` // set during policy update
}

// MatchSourceType Structure
type MatchSourceType struct {
	Path string `json:"path,omitempty"`
}

// ProcessPathType Structure
type ProcessPathType struct {
	Path       string            `json:"path,omitempty"`
	ExecName   string            `json:"execname,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// ProcessDirectoryType Structure
type ProcessDirectoryType struct {
	Directory  string            `json:"dir"`
	Recursive  bool              `json:"recursive,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// ProcessPatternType Structure
type ProcessPatternType struct {
	Pattern   string `json:"pattern"`
	OwnerOnly bool   `json:"ownerOnly,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// ProcessType Structure
type ProcessType struct {
	MatchPaths       []ProcessPathType      `json:"matchPaths,omitempty"`
	MatchDirectories []ProcessDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []ProcessPatternType   `json:"matchPatterns,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// FilePathType Structure
type FilePathType struct {
	Path       string            `json:"path"`
	ReadOnly   bool              `json:"readOnly,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// FileDirectoryType Structure
type FileDirectoryType struct {
	Directory  string            `json:"dir"`
	ReadOnly   bool              `json:"readOnly,omitempty"`
	Recursive  bool              `json:"recursive,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// FilePatternType Structure
type FilePatternType struct {
	Pattern   string `json:"pattern"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
	OwnerOnly bool   `json:"ownerOnly,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// FileType Structure
type FileType struct {
	MatchPaths       []FilePathType      `json:"matchPaths,omitempty"`
	MatchDirectories []FileDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []FilePatternType   `json:"matchPatterns,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// NetworkProtocolType Structure
type NetworkProtocolType struct {
	Protocol   string            `json:"protocol"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// NetworkType Structure
type NetworkType struct {
	MatchProtocols []NetworkProtocolType `json:"matchProtocols,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// CapabilitiesCapabilityType Structure
type CapabilitiesCapabilityType struct {
	Capability string            `json:"capability"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// CapabilitiesType Structure
type CapabilitiesType struct {
	MatchCapabilities []CapabilitiesCapabilityType `json:"matchCapabilities,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action,omitempty"`
}

// SyscallFromSourceType Structure
type SyscallFromSourceType struct {
	Path      string `json:"path,omitempty"`
	Dir       string `json:"dir,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
}

// SyscallMatchType Structure
type SyscallMatchType struct {
	Syscalls   []string                `json:"syscall,omitempty"`
	FromSource []SyscallFromSourceType `json:"fromSource,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
}

// SyscallMatchPathType Structure
type SyscallMatchPathType struct {
	Path       string                  `json:"path,omitempty"`
	Recursive  bool                    `json:"recursive,omitempty"`
	Syscalls   []string                `json:"syscall,omitempty"`
	FromSource []SyscallFromSourceType `json:"fromSource,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
}

// SyscallsType Structure
type SyscallsType struct {
	MatchSyscalls []SyscallMatchType     `json:"matchSyscalls,omitempty"`
	MatchPaths    []SyscallMatchPathType `json:"matchPaths,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
}

// PresetName type
type PresetName string

// PresetType Structure
type PresetType struct {
	Name   PresetName `json:"name,omitempty"`
	Action string     `json:"action,omitempty"`
}

const (
	// AnonMapExec Preset
	AnonMapExec PresetName = "anonymousMapExec"
	// FilelessExec Preset
	FilelessExec PresetName = "filelessExec"
	// ProtectEnv Preset
	ProtectEnv PresetName = "protectEnv"
	// Exec Preset
	Exec PresetName = "exec"
	// ProtectProc Preset
	ProtectProc PresetName = "protectProc"
)

// SecuritySpec Structure
type SecuritySpec struct {
	Selector SelectorType `json:"selector"`

	Process      ProcessType      `json:"process,omitempty"`
	File         FileType         `json:"file,omitempty"`
	Network      NetworkType      `json:"network,omitempty"`
	Capabilities CapabilitiesType `json:"capabilities,omitempty"`
	Syscalls     SyscallsType     `json:"syscalls,omitempty"`
	Presets      []PresetType     `json:"presets,omitempty"`

	AppArmor string `json:"apparmor,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action"`
}

// SecurityPolicy Structure
type SecurityPolicy struct {
	Metadata map[string]string `json:"metadata"`
	Spec     SecuritySpec      `json:"spec"`
}

// ========================== //
// == Host Security Policy == //
// ========================== //

// NodeSelectorType Structure
type NodeSelectorType struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
	Identities  []string          `json:"identities,omitempty"` // set during policy update
}

// HostSecuritySpec Structure
type HostSecuritySpec struct {
	NodeSelector NodeSelectorType `json:"nodeSelector"`

	Process      ProcessType      `json:"process,omitempty"`
	File         FileType         `json:"file,omitempty"`
	Network      NetworkType      `json:"network,omitempty"`
	Capabilities CapabilitiesType `json:"capabilities,omitempty"`
	Syscalls     SyscallsType     `json:"syscalls,omitempty"`

	AppArmor string `json:"apparmor,omitempty"`

	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`
	Action   string   `json:"action"`
}

// HostSecurityPolicy Structure
type HostSecurityPolicy struct {
	Metadata map[string]string `json:"metadata"`
	Spec     HostSecuritySpec  `json:"spec"`
}

// DefaultPosture Structure
type DefaultPosture struct {
	FileAction         string `json:"file,omitempty"`
	NetworkAction      string `json:"network,omitempty"`
	CapabilitiesAction string `json:"capabilties,omitempty"`
}

// Visibility Structure
type Visibility struct {
	File         bool `json:"file,omitempty"`
	Process      bool `json:"process,omitempty"`
	Network      bool `json:"network,omitempty"`
	Capabilities bool `json:"capabilties,omitempty"`
	DNS          bool `json:"dns,omitempty"`
}

// ================== //
// == SELinux Rule == //
// ================== //

// SELinuxRule Structure
type SELinuxRule struct {
	SubjectLabel string
	SubjectPath  string

	ObjectLabel string
	ObjectPath  string

	Permissive bool

	Directory bool
	Recursive bool

	Pattern bool
}

// ================== //
// == Process Tree == //
// ================== //

// PidMap for host pid -> process node
type PidMap map[uint32]PidNode

// PidNode Structure
type PidNode struct {
	PidID uint32
	MntID uint32

	HostPPID uint32
	HostPID  uint32

	PPID uint32
	PID  uint32
	UID  uint32

	ParentExecPath string
	ExecPath       string

	Source string
	Args   string

	Exited     bool
	ExitedTime time.Time
}

// =============== //
// == KVM Agent == //
// =============== //

// KubeArmorHostPolicyEventCallback Function
type KubeArmorHostPolicyEventCallback func(K8sKubeArmorHostPolicyEvent) pb.PolicyStatus
