package monitor

import "regexp"

// ===================== //
// == Const. Vaiables == //
// ===================== //

var (
	dockerPattern = regexp.MustCompile(`\d+:.+:/docker/([0-9a-f]{64})`)
	kubePattern1  = regexp.MustCompile(`\d+:.+:/docker/pod[^/]+/([0-9a-f]{64})`)
	kubePattern2  = regexp.MustCompile(`\d+:.+:/kubepods/[^/]+/pod[^/]+/([0-9a-f]{64})`)
)

const (
	// file
	SYS_OPEN  = 2
	SYS_CLOSE = 3

	// network
	SYS_SOCKET  = 41
	SYS_CONNECT = 42
	SYS_ACCEPT  = 43
	SYS_BIND    = 49
	SYS_LISTEN  = 50

	// process
	SYS_EXECVE   = 59
	SYS_EXECVEAT = 322
	DO_EXIT      = 351

	// capabilities
	CAP_CAPABLE = 352
)

const (
	SYSPOL_PROC     = 1
	SYSPOL_FILE     = 2
	SYSPOL_PROCFILE = 3
)

// ======================= //
// == Namespace Context == //
// ======================= //

// NsKey Structure
type NsKey struct {
	PidNS uint32
	MntNS uint32
}

// ===================== //
// == Syscall Context == //
// ===================== //

// SyscallContext Structure
type SyscallContext struct {
	Ts uint64

	PidID uint32
	MntID uint32

	HostPID uint32
	PPID    uint32
	PID     uint32
	TID     uint32
	UID     uint32

	EventID int32
	Argnum  int32
	Retval  int64

	Comm [16]byte
}

// ContextCombined Structure
type ContextCombined struct {
	ContainerID string
	ContextSys  SyscallContext
	ContextArgs []interface{}
}

// ================= //
// == Skb Context == //
// ================= //

// SkbContext Structure
type SkbContext struct {
	Ts uint64

	PidID uint32
	MntID uint32

	HostPID uint32

	L4Proto uint8
	_       [3]uint8

	SrcAddr uint32
	DstAddr uint32

	SPort uint16
	Dport uint16

	_ uint32

	NetworkKey uint64
}
