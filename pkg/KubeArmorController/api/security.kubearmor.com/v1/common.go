// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package v1

// +kubebuilder:validation:Minimum:=1
// +kubebuilder:validation:Maximum:=10
type SeverityType int

type NodeSelectorType struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// +kubebuilder:validation:Pattern=^[^\/]+$
type MatchBinType string

// +kubebuilder:validation:Pattern=^\/+.*[^\/]$
type MatchPathType string

// +kubebuilder:validation:Pattern=^\/$|^\/.*\/$
type MatchDirectoryType string

// +kubebuilder:validation:Pattern=(^\/+.*[^\/]$)|(^\/$|^\/.*\/$)
type MatchSyscallPathType string

type MatchSourceType struct {
	Path MatchPathType `json:"path,omitempty"`
}

type ProcessPathType struct {
	// +kubebuilder:validation:Optional
	Path MatchPathType `json:"path,omitempty"`

	// +kubebuilder:validation:Optional
	ExecName MatchBinType `json:"execname,omitempty"`

	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type ProcessDirectoryType struct {
	Directory MatchDirectoryType `json:"dir"`

	// +kubebuilder:validation:Optional
	Recursive bool `json:"recursive,omitempty"`
	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type ProcessPatternType struct {
	Pattern string `json:"pattern"`

	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type ProcessType struct {
	MatchPaths       []ProcessPathType      `json:"matchPaths,omitempty"`
	MatchDirectories []ProcessDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []ProcessPatternType   `json:"matchPatterns,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type FilePathType struct {
	Path MatchPathType `json:"path"`

	// +kubebuilder:validation:Optional
	ReadOnly bool `json:"readOnly,omitempty"`
	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type FileDirectoryType struct {
	Directory MatchDirectoryType `json:"dir"`

	// +kubebuilder:validation:Optional
	Recursive bool `json:"recursive,omitempty"`
	// +kubebuilder:validation:Optional
	ReadOnly bool `json:"readOnly,omitempty"`
	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type FilePatternType struct {
	Pattern string `json:"pattern"`

	// +kubebuilder:validation:Optional
	ReadOnly bool `json:"readOnly,omitempty"`
	// +kubebuilder:validation:Optional
	OwnerOnly bool `json:"ownerOnly,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type FileType struct {
	MatchPaths       []FilePathType      `json:"matchPaths,omitempty"`
	MatchDirectories []FileDirectoryType `json:"matchDirectories,omitempty"`
	MatchPatterns    []FilePatternType   `json:"matchPatterns,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// +kubebuilder:validation:Pattern=(tcp|TCP|udp|UDP|raw|RAW|icmp|ICMP|icmpv6|ICMPV6|sctp|SCTP|stream|STREAM|dgram|DGRAM|rdm|RDM|seqpacket|SEQPACKET|dccp|DCCP|packet|PACKET|all|ALL)$
type MatchNetworkProtocolStringType string

type MatchNetworkProtocolType struct {
	Protocol MatchNetworkProtocolStringType `json:"protocol"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type MatchHostNetworkProtocolType struct {
	Protocol   MatchNetworkProtocolStringType `json:"protocol"`
	FromSource []MatchSourceType              `json:"fromSource"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type NetworkType struct {
	MatchProtocols []MatchNetworkProtocolType `json:"matchProtocols,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type HostNetworkType struct {
	MatchProtocols []MatchHostNetworkProtocolType `json:"matchProtocols,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// +kubebuilder:validation:Pattern=(chown|dac_override|dac_read_search|fowner|fsetid|kill|setgid|setuid|setpcap|linux_immutable|net_bind_service|net_broadcast|net_admin|net_raw|ipc_lock|ipc_owner|sys_module|sys_rawio|sys_chroot|sys_ptrace|sys_pacct|sys_admin|sys_boot|sys_nice|sys_resource|sys_time|sys_tty_config|mknod|lease|audit_write|audit_control|setfcap|mac_override|mac_admin)$
type MatchCapabilitiesStringType string

type MatchCapabilitiesType struct {
	Capability MatchCapabilitiesStringType `json:"capability"`

	// +kubebuilder:validation:optional
	FromSource []MatchSourceType `json:"fromSource,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type MatchHostCapabilitiesType struct {
	Capability MatchCapabilitiesStringType `json:"capability"`
	FromSource []MatchSourceType           `json:"fromSource"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type CapabilitiesType struct {
	MatchCapabilities []MatchCapabilitiesType `json:"matchCapabilities,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

type HostCapabilitiesType struct {
	MatchCapabilities []MatchHostCapabilitiesType `json:"matchCapabilities,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

// +kubebuilder:validation:Enum=Allow;Audit;Block
type ActionType string

// +kubebuilder:validation:Enum=read;write;open;close;stat;fstat;lstat;poll;lseek;mmap;mprotect;munmap;brk;rt_sigaction;rt_sigprocmask;rt_sigreturn;ioctl;pread64;pwrite64;readv;writev;access;pipe;select;sched_yield;mremap;msync;mincore;madvise;shmget;shmat;shmctl;dup;dup2;pause;nanosleep;getitimer;alarm;setitimer;getpid;sendfile;socket;connect;accept;sendto;recvfrom;sendmsg;recvmsg;shutdown;bind;listen;getsockname;getpeername;socketpair;setsockopt;getsockopt;clone;fork;vfork;execve;exit;wait4;kill;uname;semget;semop;semctl;shmdt;msgget;msgsnd;msgrcv;msgctl;fcntl;flock;fsync;fdatasync;truncate;ftruncate;getdents;getcwd;chdir;fchdir;rename;mkdir;rmdir;creat;link;unlink;symlink;readlink;chmod;fchmod;chown;fchown;lchown;umask;gettimeofday;getrlimit;getrusage;sysinfo;times;ptrace;getuid;syslog;getgid;setuid;setgid;geteuid;getegid;setpgid;getppid;getpgrp;setsid;setreuid;setregid;getgroups;setgroups;setresuid;getresuid;setresgid;getresgid;getpgid;setfsuid;setfsgid;getsid;capget;capset;rt_sigpending;rt_sigtimedwait;rt_sigqueueinfo;rt_sigsuspend;sigaltstack;utime;mknod;uselib;personality;ustat;statfs;fstatfs;sysfs;getpriority;setpriority;sched_setparam;sched_getparam;sched_setscheduler;sched_getscheduler;sched_get_priority_max;sched_get_priority_min;sched_rr_get_interval;mlock;munlock;mlockall;munlockall;vhangup;modify_ldt;pivot_root;_sysctl;prctl;arch_prctl;adjtimex;setrlimit;chroot;sync;acct;settimeofday;mount;umount2;swapon;swapoff;reboot;sethostname;setdomainname;iopl;ioperm;create_module;init_module;delete_module;get_kernel_syms;query_module;quotactl;nfsservctl;getpmsg;putpmsg;afs_syscall;tuxcall;security;gettid;readahead;setxattr;lsetxattr;fsetxattr;getxattr;lgetxattr;fgetxattr;listxattr;llistxattr;flistxattr;removexattr;lremovexattr;fremovexattr;tkill;time;futex;sched_setaffinity;sched_getaffinity;set_thread_area;io_setup;io_destroy;io_getevents;io_submit;io_cancel;get_thread_area;lookup_dcookie;epoll_create;epoll_ctl_old;epoll_wait_old;remap_file_pages;getdents64;set_tid_address;restart_syscall;semtimedop;fadvise64;timer_create;timer_settime;timer_gettime;timer_getoverrun;timer_delete;clock_settime;clock_gettime;clock_getres;clock_nanosleep;exit_group;epoll_wait;epoll_ctl;tgkill;utimes;vserver;mbind;set_mempolicy;get_mempolicy;mq_open;mq_unlink;mq_timedsend;mq_timedreceive;mq_notify;mq_getsetattr;kexec_load;waitid;add_key;request_key;keyctl;ioprio_set;ioprio_get;inotify_init;inotify_add_watch;inotify_rm_watch;migrate_pages;openat;mkdirat;mknodat;fchownat;futimesat;newfstatat;unlinkat;renameat;linkat;symlinkat;readlinkat;fchmodat;faccessat;pselect6;ppoll;unshare;set_robust_list;get_robust_list;splice;tee;sync_file_range;vmsplice;move_pages;utimensat;epoll_pwait;signalfd;timerfd_create;eventfd;fallocate;timerfd_settime;timerfd_gettime;accept4;signalfd4;eventfd2;epoll_create1;dup3;pipe2;inotify_init1;preadv;pwritev;rt_tgsigqueueinfo;perf_event_open;recvmmsg;fanotify_init;fanotify_mark;prlimit64;name_to_handle_at;open_by_handle_at;clock_adjtime;syncfs;sendmmsg;setns;getcpu;process_vm_readv;process_vm_writev;kcmp;finit_module;sched_setattr;sched_getattr;renameat2;seccomp;getrandom;memfd_create;kexec_file_load;bpf;execveat;userfaultfd;membarrier;mlock2;copy_file_range;preadv2;pwritev2;pkey_mprotect;pkey_alloc;pkey_free;statx;io_pgetevents;rseq
type Syscall string

type SyscallFromSourceType struct {
	Path      MatchPathType `json:"path,omitempty"`
	Dir       string        `json:"dir,omitempty"`
	Recursive bool          `json:"recursive,omitempty"`
}

type SyscallMatchType struct {
	Syscalls   []Syscall               `json:"syscall,omitempty"`
	FromSource []SyscallFromSourceType `json:"fromSource,omitempty"`
}

type SyscallMatchPathType struct {
	Path       MatchSyscallPathType    `json:"path,omitempty"`
	Recursive  bool                    `json:"recursive,omitempty"`
	Syscalls   []Syscall               `json:"syscall,omitempty"`
	FromSource []SyscallFromSourceType `json:"fromSource,omitempty"`
}

type SyscallsType struct {
	MatchSyscalls []SyscallMatchType     `json:"matchSyscalls,omitempty"`
	MatchPaths    []SyscallMatchPathType `json:"matchPaths,omitempty"`

	// +kubebuilder:validation:optional
	Severity SeverityType `json:"severity,omitempty"`
	// +kubebuilder:validation:optional
	Tags []string `json:"tags,omitempty"`
	// +kubebuilder:validation:optional
	Message string `json:"message,omitempty"`
}

type PresetName string

type PresetType struct {
	Name PresetName `json:"name,omitempty"`
	// +kubebuilder:validation:optional
	Action ActionType `json:"action,omitempty"`
}

const (
	// ProtectEnv Preset
	ProtectEnv PresetName = "protectEnv"
	// FilelessExec Preset
	FilelessExec PresetName = "filelessExec"
	// Exec Preset
	Exec PresetName = "exec"
	// ProtectProc Preset
	ProtectProc PresetName = "protectProc"
)
