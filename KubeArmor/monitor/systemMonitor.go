// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

// Package monitor is the component responsible for monitoring syscalls and communicating with eBPF Programs
package monitor

import (
	"encoding/binary"
	"sync"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// SystemMonitor Constant Values
const (
	PermissionDenied = -13
	MaxStringLen     = 4096
	PinPath          = "/sys/fs/bpf"
	visibilityOff    = uint32(1)
	visibilityOn     = uint32(0)
	// how many event the channel can hold
	SyscallChannelSize   = 1 << 13 //8192
	DefaultVisibilityKey = uint32(0xc0ffee)
)

// ======================= /=/
// == Namespace Context == //
// ======================= //

// NsKey Structure
type NsKey struct {
	PidNS uint32
	MntNS uint32
}

// NsVisibility Structure
type NsVisibility struct {
	NsKeys     []NsKey
	File       bool
	Process    bool
	Capability bool
	Network    bool
	DNS        bool
	IMA        bool
}

// ===================== //
// == Syscall Context == //
// ===================== //

// SyscallContext Structure
type SyscallContext struct {
	Ts uint64

	PidID uint32
	MntID uint32

	HostPPID uint32
	HostPID  uint32

	PPID uint32
	PID  uint32
	UID  uint32

	EventID int32
	Argnum  int32
	Retval  int64

	Comm [16]byte
	Cwd  [80]byte
	TTY  [64]byte
	OID  uint32

	// exec events
	ExecID uint64
	Hash   uint8
}

// HashContext Structure
type HashContext struct {
	ProcessHash  string
	ParentHash   string
	ResourceHash string
	HashAlgo     uint32
}

// ContextCombined Structure
type ContextCombined struct {
	ContainerID string
	ContextSys  SyscallContext
	HashData    HashContext
	ContextArgs []interface{}
}

// ======================= //
// == Container Monitor == //
// ======================= //

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

// Monitor is core module implemented by
// os-dependent monitoring system
type Monitor interface {
	// setting-up core module
	Init() error
	// cleanup monitor resources
	Destroy() error
	// visibility configuration mgmt
	UpdateNsVisibility(action string, nsKey NsKey, visibility tp.Visibility)
	UpdateDefaultVisibility()
	// configuration mgmt
	UpdateConfiguration(key, value uint32) error
	// throttling configuration mgmt
	UpdateThrottlingConfig()
	// get context channel
	GetContextChannel() <-chan ContextCombined
	// start tracing system events
	TraceEvents()
}

// every concrete type Monitor should implement this
// to initialize the monitor component
type InitMonitor interface {
	NewMonitor(*MonitorState) Monitor
}

// should be implemented by (os-dependent) systemMonitor
var (
	_ InitMonitor = (*SystemMonitor)(nil)
)

// ima initializer
type InitImaHash interface {
	NewImaHash(feeder *fd.Feeder, pinPath string) ImaHash
}

var (
	_ InitImaHash = (*SystemMonitor)(nil)
)

type MonitorState struct {
	// node
	Node     *tp.Node
	NodeLock **sync.RWMutex

	// logs
	Logger *fd.Feeder

	// container id -> container
	Containers     *map[string]tp.Container
	ContainersLock **sync.RWMutex

	// container id -> host pid
	ActiveHostPidMap *map[string]tp.PidMap
	ActivePidMapLock **sync.RWMutex

	// PidID + MntID -> container id
	NsMap     map[NsKey]string
	NsMapLock *sync.RWMutex

	// namespace -> visibility
	NamespacePidsMap map[string]NsVisibility

	// lists to skip
	UntrackedNamespaces []string

	// podLabelsMap
	PodLabelsMap     map[string]string
	PodLabelsMapLock *sync.RWMutex

	execLogMap     map[uint32]tp.Log
	execLogMapLock *sync.RWMutex

	// monitor lock
	MonitorLock **sync.RWMutex

	Status          bool
	UptimeTimeStamp float64
	HostByteOrder   binary.ByteOrder
}

// SystemMonitor Structure
type SystemMonitor struct {
	// monitor state
	*MonitorState
	// monitor module
	Monitor
	// IMA hash
	ImaHash
}

// NewSystemMonitor Function
func NewSystemMonitor(node *tp.Node, nodeLock **sync.RWMutex, logger *fd.Feeder, containers *map[string]tp.Container, containersLock **sync.RWMutex,
	activeHostPidMap *map[string]tp.PidMap, activePidMapLock **sync.RWMutex, monitorLock **sync.RWMutex) *SystemMonitor {
	mon := new(SystemMonitor)
	ms := new(MonitorState)
	ms.Node = node
	ms.NodeLock = nodeLock
	ms.Logger = logger

	ms.Containers = containers
	ms.ContainersLock = containersLock

	ms.ActiveHostPidMap = activeHostPidMap
	ms.ActivePidMapLock = activePidMapLock

	ms.NsMap = make(map[NsKey]string)
	ms.NsMapLock = new(sync.RWMutex)

	ms.MonitorLock = monitorLock

	ms.Status = true
	ms.UptimeTimeStamp = kl.GetUptimeTimestamp()
	ms.HostByteOrder = binary.LittleEndian

	ms.execLogMap = map[uint32]tp.Log{}
	ms.execLogMapLock = new(sync.RWMutex)

	ms.NamespacePidsMap = make(map[string]NsVisibility)

	// assign the value of untracked ns from GlobalCfg
	ms.UntrackedNamespaces = make([]string, len(cfg.GlobalCfg.ConfigUntrackedNs))
	copy(ms.UntrackedNamespaces, cfg.GlobalCfg.ConfigUntrackedNs)

	ms.PodLabelsMap = make(map[string]string)
	ms.PodLabelsMapLock = new(sync.RWMutex)

	mon.MonitorState = ms

	mon.Monitor = mon.NewMonitor(ms)

	return mon
}

// DestroySystemMonitor Function
func (mon *SystemMonitor) DestroySystemMonitor() error {
	return mon.Monitor.Destroy()
}
