// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package types

import (
	"regexp"
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

	NamespaceName      string `json:"namespaceName"`
	ContainerGroupName string `json:"containerGroupName"`

	AppArmorProfile string `json:"apparmorProfile"`

	// == //

	PidNS uint32 `json:"pidns"`
	MntNS uint32 `json:"mntns"`

	// == //

	PolicyEnabled int `json:"policyEnabled"`

	ProcessVisibilityEnabled      bool `json:"processVisibilityEnabled"`
	FileVisibilityEnabled         bool `json:"fileVisibilityEnabled"`
	NetworkVisibilityEnabled      bool `json:"networkVisibilityEnabled"`
	CapabilitiesVisibilityEnabled bool `json:"capabilitiesVisibilityEnabled"`
}

// ContainerGroup Structure
type ContainerGroup struct {
	NamespaceName      string `json:"namespaceName"`
	ContainerGroupName string `json:"containerGroupName"`

	Labels     map[string]string `json:"labels"`
	Identities []string          `json:"identities"`

	Containers       []string `json:"containers"`
	AppArmorProfiles []string `json:"apparmorProfiles"`

	SecurityPolicies []SecurityPolicy `json:"securityPolicies"`

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

// K8sPod Structure
type K8sPod struct {
	Metadata    map[string]string
	Annotations map[string]string
	Labels      map[string]string
	Containers  map[string]string
}

// K8sPodEvent Structure
type K8sPodEvent struct {
	Type   string `json:"type"`
	Object v1.Pod `json:"object"`
}

// SecurityPolicyStatus Structure
type SecurityPolicyStatus struct {
	PolicyStatus string `json:"status,omitempty"`
}

// K8sKubeArmorPolicyEvent Structure
type K8sKubeArmorPolicyEvent struct {
	Type   string             `json:"type"`
	Object K8sKubeArmorPolicy `json:"object"`
}

// K8sKubeArmorPolicy Structure
type K8sKubeArmorPolicy struct {
	Metadata metav1.ObjectMeta    `json:"metadata"`
	Spec     SecuritySpec         `json:"spec"`
	Status   SecurityPolicyStatus `json:"status,omitempty"`
}

// K8sKubeArmorPolicies Structure
type K8sKubeArmorPolicies struct {
	Items []K8sKubeArmorPolicy `json:"items"`
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
	NamespaceName string `json:"namespaceName,omitempty"`
	PodName       string `json:"podName,omitempty"`

	// container
	ContainerID   string `json:"containerID,omitempty"`
	ContainerName string `json:"containerName,omitempty"`

	// common
	HostPID int32 `json:"hostPid"`
	PPID    int32 `json:"ppid"`
	PID     int32 `json:"pid"`
	UID     int32 `json:"uid"`

	// policy
	PolicyName string `json:"policyName,omitempty"`

	// severity, tags, message
	Severity string `json:"severity,omitempty"`
	Tags     string `json:"tags,omitempty"`
	Message  string `json:"message,omitempty"`

	// log
	Type      string `json:"type"`
	Source    string `json:"source"`
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
	Data      string `json:"data,omitempty"`
	Action    string `json:"action,omitempty"`
	Result    string `json:"result"`

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

	Regexp *regexp.Regexp

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
)

// SelectorType Structure
type SelectorType struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
	Identities  []string          `json:"identities,omitempty"` // set during policy update
}

// MatchSourceType Structure
type MatchSourceType struct {
	Path      string `json:"path,omitempty"`
	Directory string `json:"dir,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
}

// ProcessPathType Structure
type ProcessPathType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Path       string            `json:"path"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// ProcessDirectoryType Structure
type ProcessDirectoryType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Directory  string            `json:"dir"`
	Recursive  bool              `json:"recursive,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// ProcessPatternType Structure
type ProcessPatternType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Pattern   string `json:"pattern"`
	OwnerOnly bool   `json:"ownerOnly,omitempty"`

	Action string `json:"action,omitempty"`
}

// ProcessType Structure
type ProcessType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	MatchPaths       []ProcessPathType      `json:"matchPaths,omitempty"`
	MatchDirectories []ProcessDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []ProcessPatternType   `json:"matchPatterns,omitempty"`

	Action string `json:"action,omitempty"`
}

// FilePathType Structure
type FilePathType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Path       string            `json:"path"`
	ReadOnly   bool              `json:"readOnly,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// FileDirectoryType Structure
type FileDirectoryType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Directory  string            `json:"dir"`
	ReadOnly   bool              `json:"readOnly,omitempty"`
	Recursive  bool              `json:"recursive,omitempty"`
	OwnerOnly  bool              `json:"ownerOnly,omitempty"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// FilePatternType Structure
type FilePatternType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Pattern   string `json:"pattern"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
	OwnerOnly bool   `json:"ownerOnly,omitempty"`

	Action string `json:"action,omitempty"`
}

// FileType Structure
type FileType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	MatchPaths       []FilePathType      `json:"matchPaths,omitempty"`
	MatchDirectories []FileDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []FilePatternType   `json:"matchPatterns,omitempty"`

	Action string `json:"action,omitempty"`
}

// NetworkProtocolType Structure
type NetworkProtocolType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Protocol   string            `json:"protocol"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// NetworkType Structure
type NetworkType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	MatchProtocols []NetworkProtocolType `json:"matchProtocols,omitempty"`

	Action string `json:"action,omitempty"`
}

// CapabilitiesCapabilityType Structure
type CapabilitiesCapabilityType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	Capability string            `json:"capability"`
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	Action string `json:"action,omitempty"`
}

// CapabilitiesType Structure
type CapabilitiesType struct {
	Severity int      `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

	MatchCapabilities []CapabilitiesCapabilityType `json:"matchCapabilities,omitempty"`

	Action string `json:"action,omitempty"`
}

// SecuritySpec Structure
type SecuritySpec struct {
	Severity int      `json:"severity"`
	Tags     []string `json:"tags,omitempty"`
	Message  string   `json:"message,omitempty"`

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
	PidID uint32
	MntID uint32

	HostPPID uint32
	HostPID  uint32

	PPID uint32
	PID  uint32
	UID  uint32

	Comm     string
	ExecPath string

	Exited     bool
	ExitedTime time.Time
}
