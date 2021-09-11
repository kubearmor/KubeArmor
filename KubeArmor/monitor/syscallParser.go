// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package monitor

// ========================================================= //
// KubeArmor utilizes Tracee's system call parsing functions //
// developed by Aqua Security (https://aquasec.com).         //
// ========================================================= //

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// ===================== //
// == Const. Vaiables == //
// ===================== //

// Data Types
const (
	intT       uint8 = 1
	strT       uint8 = 10
	strArrT    uint8 = 11
	sockAddrT  uint8 = 12
	openFlagsT uint8 = 13
	execFlagsT uint8 = 14
	sockDomT   uint8 = 15
	sockTypeT  uint8 = 16
	capT       uint8 = 17
	syscallT   uint8 = 18
)

// ======================= //
// == Parsing Functions == //
// ======================= //

// readContextFromBuff Function
func readContextFromBuff(buff io.Reader) (SyscallContext, error) {
	var res SyscallContext
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

// readInt8FromBuff Function
func readInt8FromBuff(buff io.Reader) (int8, error) {
	var res int8
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

// readInt16FromBuff Function
func readInt16FromBuff(buff io.Reader) (int16, error) {
	var res int16
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

// readUInt16BigendFromBuff Function
func readUInt16BigendFromBuff(buff io.Reader) (uint16, error) {
	var res uint16
	err := binary.Read(buff, binary.BigEndian, &res)
	return res, err
}

// readInt32FromBuff Function
func readInt32FromBuff(buff io.Reader) (int32, error) {
	var res int32
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

// readUInt32FromBuff Function
func readUInt32FromBuff(buff io.Reader) (uint32, error) {
	var res uint32
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

// readUInt32BigendFromBuff Function
func readUInt32BigendFromBuff(buff io.Reader) (uint32, error) {
	var res uint32
	err := binary.Read(buff, binary.BigEndian, &res)
	return res, err
}

// readByteSliceFromBuff Function
func readByteSliceFromBuff(buff io.Reader, len int) ([]byte, error) {
	res := make([]byte, len)
	if err := binary.Read(buff, binary.LittleEndian, &res); err != nil {
		return nil, fmt.Errorf("error reading byte array: %v", err)
	}
	return res, nil
}

// readStringFromBuff Function
func readStringFromBuff(buff io.Reader) (string, error) {
	var err error
	size, err := readInt32FromBuff(buff)
	if err != nil {
		return "", fmt.Errorf("error reading string size: %v", err)
	}
	res, err := readByteSliceFromBuff(buff, int(size-1)) // last byte is string terminating null
	defer func() {
		_, _ = readInt8FromBuff(buff) // discard last byte which is string terminating null
	}()
	if err != nil {
		return "", fmt.Errorf("error reading string arg: %v", err)
	}
	return string(res), nil
}

// readUint32IP Function
func readUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

// readSockaddrFromBuff Function
func readSockaddrFromBuff(buff io.Reader) (map[string]string, error) {
	res := make(map[string]string, 3)
	family, err := readInt16FromBuff(buff)
	if err != nil {
		return nil, err
	}
	res["sa_family"] = getSocketDomain(uint32(family))
	switch family {
	case 1: // AF_UNIX
		/*
			http://man7.org/linux/man-pages/man7/unix.7.html
			struct sockaddr_un {
					sa_family_t sun_family;     // AF_UNIX
					char        sun_path[108];  // Pathname
			};
		*/
		var sunPathBuf [108]byte
		err := binary.Read(buff, binary.LittleEndian, &sunPathBuf)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_un: %v", err)
		}

		sunPath := ""
		for i, v := range sunPathBuf {
			if v == '\u0000' { // null termination
				sunPath = string(sunPathBuf[:i])
				break
			}
		}
		res["sun_path"] = sunPath
	case 2: // AF_INET
		/*
			http://man7.org/linux/man-pages/man7/ip.7.html
			struct sockaddr_in {
				sa_family_t    sin_family; // address family: AF_INET
				in_port_t      sin_port;   // port in network byte order
				struct in_addr sin_addr;   // internet address
			};
			struct in_addr {
				uint32_t       s_addr;     // address in network byte order
			};
		*/
		port, err := readUInt16BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_port"] = strconv.Itoa(int(port))

		addr, err := readUInt32BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_addr"] = readUint32IP(addr)
	}
	return res, nil
}

// getOpenFlags Function
func getOpenFlags(flags uint32) string {
	// readOpenFlags prints the `flags` bitmask argument of the `open` syscall
	// http://man7.org/linux/man-pages/man2/open.2.html
	// https://elixir.bootlin.com/linux/v5.5.3/source/include/uapi/asm-generic/fcntl.h

	var f []string

	if flags&01 == 01 {
		f = append(f, "O_WRONLY")
	} else if flags&02 == 02 {
		f = append(f, "O_RDWR")
	} else {
		f = append(f, "O_RDONLY")
	}

	if flags&0100 == 0100 {
		f = append(f, "O_CREAT")
	}
	if flags&0200 == 0200 {
		f = append(f, "O_EXCL")
	}
	if flags&0400 == 0400 {
		f = append(f, "O_NOCTTY")
	}
	if flags&01000 == 01000 {
		f = append(f, "O_TRUNC")
	}
	if flags&02000 == 02000 {
		f = append(f, "O_APPEND")
	}
	if flags&04000 == 04000 {
		f = append(f, "O_NONBLOCK")
	}
	if flags&04010000 == 04010000 {
		f = append(f, "O_SYNC")
	}
	if flags&020000 == 020000 {
		f = append(f, "O_ASYNC")
	}
	if flags&0100000 == 0100000 {
		f = append(f, "O_LARGEFILE")
	}
	if flags&0200000 == 0200000 {
		f = append(f, "O_DIRECTORY")
	}
	if flags&0400000 == 0400000 {
		f = append(f, "O_NOFOLLOW")
	}
	if flags&02000000 == 02000000 {
		f = append(f, "O_CLOEXEC")
	}
	if flags&040000 == 040000 {
		f = append(f, "O_DIRECT")
	}
	if flags&01000000 == 01000000 {
		f = append(f, "O_NOATIME")
	}
	if flags&010000000 == 010000000 {
		f = append(f, "O_PATH")
	}
	if flags&020000000 == 020000000 {
		f = append(f, "O_TMPFILE")
	}

	return strings.Join(f, "|")
}

// getExecFlags Function
func getExecFlags(flags uint32) string {
	// readExecFlags prints the `flags` bitmask argument of the `execve` syscall
	// http://man7.org/linux/man-pages/man2/axecveat.2.html
	// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/fcntl.h#L94

	var f []string

	if flags&0x100 == 0x100 {
		f = append(f, "AT_EMPTY_PATH")
	}
	if flags&0x1000 == 0x1000 {
		f = append(f, "AT_SYMLINK_NOFOLLOW")
	}
	if len(f) == 0 {
		f = append(f, "0")
	}

	return strings.Join(f, "|")
}

// getSocketDomain Function
func getSocketDomain(sd uint32) string {
	// readSocketDomain prints the `domain` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html

	var socketDomains = map[uint32]string{
		0:  "AF_UNSPEC",
		1:  "AF_UNIX",
		2:  "AF_INET",
		3:  "AF_AX25",
		4:  "AF_IPX",
		5:  "AF_APPLETALK",
		6:  "AF_NETROM",
		7:  "AF_BRIDGE",
		8:  "AF_ATMPVC",
		9:  "AF_X25",
		10: "AF_INET6",
		11: "AF_ROSE",
		12: "AF_DECnet",
		13: "AF_NETBEUI",
		14: "AF_SECURITY",
		15: "AF_KEY",
		16: "AF_NETLINK",
		17: "AF_PACKET",
		18: "AF_ASH",
		19: "AF_ECONET",
		20: "AF_ATMSVC",
		21: "AF_RDS",
		22: "AF_SNA",
		23: "AF_IRDA",
		24: "AF_PPPOX",
		25: "AF_WANPIPE",
		26: "AF_LLC",
		27: "AF_IB",
		28: "AF_MPLS",
		29: "AF_CAN",
		30: "AF_TIPC",
		31: "AF_BLUETOOTH",
		32: "AF_IUCV",
		33: "AF_RXRPC",
		34: "AF_ISDN",
		35: "AF_PHONET",
		36: "AF_IEEE802154",
		37: "AF_CAIF",
		38: "AF_ALG",
		39: "AF_NFC",
		40: "AF_VSOCK",
		41: "AF_KCM",
		42: "AF_QIPCRTR",
		43: "AF_SMC",
		44: "AF_XDP",
	}

	var res string

	if sdName, ok := socketDomains[sd]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(sd))
	}

	return res
}

// getSocketType Function
func getSocketType(st uint32) string {
	// readSocketType prints the `type` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html
	// https://elixir.bootlin.com/linux/v5.5.3/source/arch/mips/include/asm/socket.h

	var socketTypes = map[uint32]string{
		1:  "SOCK_STREAM",
		2:  "SOCK_DGRAM",
		3:  "SOCK_RAW",
		4:  "SOCK_RDM",
		5:  "SOCK_SEQPACKET",
		6:  "SOCK_DCCP",
		10: "SOCK_PACKET",
	}

	var f []string

	if stName, ok := socketTypes[st&0xf]; ok {
		f = append(f, stName)
	} else {
		f = append(f, strconv.Itoa(int(st)))
	}
	if st&000004000 == 000004000 {
		f = append(f, "SOCK_NONBLOCK")
	}
	if st&002000000 == 002000000 {
		f = append(f, "SOCK_CLOEXEC")
	}

	return strings.Join(f, "|")
}

// getCapabilityName Function
func getCapabilityName(cap int32) string {
	// getCapabilityName prints the `capability` bitmask argument of the `cap_capable` function
	// include/uapi/linux/capability.h

	var capabilities = map[int32]string{
		0:  "CAP_CHOWN",
		1:  "CAP_DAC_OVERRIDE",
		2:  "CAP_DAC_READ_SEARCH",
		3:  "CAP_FOWNER",
		4:  "CAP_FSETID",
		5:  "CAP_KILL",
		6:  "CAP_SETGID",
		7:  "CAP_SETUID",
		8:  "CAP_SETPCAP",
		9:  "CAP_LINUX_IMMUTABLE",
		10: "CAP_NET_BIND_SERVICE",
		11: "CAP_NET_BROADCAST",
		12: "CAP_NET_ADMIN",
		13: "CAP_NET_RAW",
		14: "CAP_IPC_LOCK",
		15: "CAP_IPC_OWNER",
		16: "CAP_SYS_MODULE",
		17: "CAP_SYS_RAWIO",
		18: "CAP_SYS_CHROOT",
		19: "CAP_SYS_PTRACE",
		20: "CAP_SYS_PACCT",
		21: "CAP_SYS_ADMIN",
		22: "CAP_SYS_BOOT",
		23: "CAP_SYS_NICE",
		24: "CAP_SYS_RESOURCE",
		25: "CAP_SYS_TIME",
		26: "CAP_SYS_TTY_CONFIG",
		27: "CAP_MKNOD",
		28: "CAP_LEASE",
		29: "CAP_AUDIT_WRITE",
		30: "CAP_AUDIT_CONTROL",
		31: "CAP_SETFCAP",
		32: "CAP_MAC_OVERRIDE",
		33: "CAP_MAC_ADMIN",
		34: "CAP_SYSLOG",
		35: "CAP_WAKE_ALARM",
		36: "CAP_BLOCK_SUSPEND",
		37: "CAP_AUDIT_READ",
	}

	var res string

	if capName, ok := capabilities[cap]; ok {
		res = capName
	} else {
		res = strconv.Itoa(int(cap))
	}

	return res
}

// getSyscallName Function
func getSyscallName(sc int32) string {
	// source: /usr/include/x86_64-linux-gnu/asm/unistd_64.h

	var syscalls = map[int32]string{
		0:   "SYS_READ",
		1:   "SYS_WRITE",
		2:   "SYS_OPEN",
		3:   "SYS_CLOSE",
		4:   "SYS_STAT",
		5:   "SYS_FSTAT",
		6:   "SYS_LSTAT",
		7:   "SYS_POLL",
		8:   "SYS_LSEEK",
		9:   "SYS_MMAP",
		10:  "SYS_MPROTECT",
		11:  "SYS_MUNMAP",
		12:  "SYS_BRK",
		13:  "SYS_RT_SIGACTION",
		14:  "SYS_RT_SIGPROCMASK",
		15:  "SYS_RT_SIGRETURN",
		16:  "SYS_IOCTL",
		17:  "SYS_PREAD64",
		18:  "SYS_PWRITE64",
		19:  "SYS_READV",
		20:  "SYS_WRITEV",
		21:  "SYS_ACCESS",
		22:  "SYS_PIPE",
		23:  "SYS_SELECT",
		24:  "SYS_SCHED_YIELD",
		25:  "SYS_MREMAP",
		26:  "SYS_MSYNC",
		27:  "SYS_MINCORE",
		28:  "SYS_MADVISE",
		29:  "SYS_SHMGET",
		30:  "SYS_SHMAT",
		31:  "SYS_SHMCTL",
		32:  "SYS_DUP",
		33:  "SYS_DUP2",
		34:  "SYS_PAUSE",
		35:  "SYS_NANOSLEEP",
		36:  "SYS_GETITIMER",
		37:  "SYS_ALARM",
		38:  "SYS_SETITIMER",
		39:  "SYS_GETPID",
		40:  "SYS_SENDFILE",
		41:  "SYS_SOCKET",
		42:  "SYS_CONNECT",
		43:  "SYS_ACCEPT",
		44:  "SYS_SENDTO",
		45:  "SYS_RECVFROM",
		46:  "SYS_SENDMSG",
		47:  "SYS_RECVMSG",
		48:  "SYS_SHUTDOWN",
		49:  "SYS_BIND",
		50:  "SYS_LISTEN",
		51:  "SYS_GETSOCKNAME",
		52:  "SYS_GETPEERNAME",
		53:  "SYS_SOCKETPAIR",
		54:  "SYS_SETSOCKOPT",
		55:  "SYS_GETSOCKOPT",
		56:  "SYS_CLONE",
		57:  "SYS_FORK",
		58:  "SYS_VFORK",
		59:  "SYS_EXECVE",
		60:  "SYS_EXIT",
		61:  "SYS_WAIT4",
		62:  "SYS_KILL",
		63:  "SYS_UNAME",
		64:  "SYS_SEMGET",
		65:  "SYS_SEMOP",
		66:  "SYS_SEMCTL",
		67:  "SYS_SHMDT",
		68:  "SYS_MSGGET",
		69:  "SYS_MSGSND",
		70:  "SYS_MSGRCV",
		71:  "SYS_MSGCTL",
		72:  "SYS_FCNTL",
		73:  "SYS_FLOCK",
		74:  "SYS_FSYNC",
		75:  "SYS_FDATASYNC",
		76:  "SYS_TRUNCATE",
		77:  "SYS_FTRUNCATE",
		78:  "SYS_GETDENTS",
		79:  "SYS_GETCWD",
		80:  "SYS_CHDIR",
		81:  "SYS_FCHDIR",
		82:  "SYS_RENAME",
		83:  "SYS_MKDIR",
		84:  "SYS_RMDIR",
		85:  "SYS_CREAT",
		86:  "SYS_LINK",
		87:  "SYS_UNLINK",
		88:  "SYS_SYMLINK",
		89:  "SYS_READLINK",
		90:  "SYS_CHMOD",
		91:  "SYS_FCHMOD",
		92:  "SYS_CHOWN",
		93:  "SYS_FCHOWN",
		94:  "SYS_LCHOWN",
		95:  "SYS_UMASK",
		96:  "SYS_GETTIMEOFDAY",
		97:  "SYS_GETRLIMIT",
		98:  "SYS_GETRUSAGE",
		99:  "SYS_SYSINFO",
		100: "SYS_TIMES",
		101: "SYS_PTRACE",
		102: "SYS_GETUID",
		103: "SYS_SYSLOG",
		104: "SYS_GETGID",
		105: "SYS_SETUID",
		106: "SYS_SETGID",
		107: "SYS_GETEUID",
		108: "SYS_GETEGID",
		109: "SYS_SETPGID",
		110: "SYS_GETPPID",
		111: "SYS_GETPGRP",
		112: "SYS_SETSID",
		113: "SYS_SETREUID",
		114: "SYS_SETREGID",
		115: "SYS_GETGROUPS",
		116: "SYS_SETGROUPS",
		117: "SYS_SETRESUID",
		118: "SYS_GETRESUID",
		119: "SYS_SETRESGID",
		120: "SYS_GETRESGID",
		121: "SYS_GETPGID",
		122: "SYS_SETFSUID",
		123: "SYS_SETFSGID",
		124: "SYS_GETSID",
		125: "SYS_CAPGET",
		126: "SYS_CAPSET",
		127: "SYS_RT_SIGPENDING",
		128: "SYS_RT_SIGTIMEDWAIT",
		129: "SYS_RT_SIGQUEUEINFO",
		130: "SYS_RT_SIGSUSPEND",
		131: "SYS_SIGALTSTACK",
		132: "SYS_UTIME",
		133: "SYS_MKNOD",
		134: "SYS_USELIB",
		135: "SYS_PERSONALITY",
		136: "SYS_USTAT",
		137: "SYS_STATFS",
		138: "SYS_FSTATFS",
		139: "SYS_SYSFS",
		140: "SYS_GETPRIORITY",
		141: "SYS_SETPRIORITY",
		142: "SYS_SCHED_SETPARAM",
		143: "SYS_SCHED_GETPARAM",
		144: "SYS_SCHED_SETSCHEDULER",
		145: "SYS_SCHED_GETSCHEDULER",
		146: "SYS_SCHED_GET_PRIORITY_MAX",
		147: "SYS_SCHED_GET_PRIORITY_MIN",
		148: "SYS_SCHED_RR_GET_INTERVAL",
		149: "SYS_MLOCK",
		150: "SYS_MUNLOCK",
		151: "SYS_MLOCKALL",
		152: "SYS_MUNLOCKALL",
		153: "SYS_VHANGUP",
		154: "SYS_MODIFY_LDT",
		155: "SYS_PIVOT_ROOT",
		156: "SYS__SYSCTL",
		157: "SYS_PRCTL",
		158: "SYS_ARCH_PRCTL",
		159: "SYS_ADJTIMEX",
		160: "SYS_SETRLIMIT",
		161: "SYS_CHROOT",
		162: "SYS_SYNC",
		163: "SYS_ACCT",
		164: "SYS_SETTIMEOFDAY",
		165: "SYS_MOUNT",
		166: "SYS_UMOUNT2",
		167: "SYS_SWAPON",
		168: "SYS_SWAPOFF",
		169: "SYS_REBOOT",
		170: "SYS_SETHOSTNAME",
		171: "SYS_SETDOMAINNAME",
		172: "SYS_IOPL",
		173: "SYS_IOPERM",
		174: "SYS_CREATE_MODULE",
		175: "SYS_INIT_MODULE",
		176: "SYS_DELETE_MODULE",
		177: "SYS_GET_KERNEL_SYMS",
		178: "SYS_QUERY_MODULE",
		179: "SYS_QUOTACTL",
		180: "SYS_NFSSERVCTL",
		181: "SYS_GETPMSG",
		182: "SYS_PUTPMSG",
		183: "SYS_AFS_SYSCALL",
		184: "SYS_TUXCALL",
		185: "SYS_SECURITY",
		186: "SYS_GETTID",
		187: "SYS_READAHEAD",
		188: "SYS_SETXATTR",
		189: "SYS_LSETXATTR",
		190: "SYS_FSETXATTR",
		191: "SYS_GETXATTR",
		192: "SYS_LGETXATTR",
		193: "SYS_FGETXATTR",
		194: "SYS_LISTXATTR",
		195: "SYS_LLISTXATTR",
		196: "SYS_FLISTXATTR",
		197: "SYS_REMOVEXATTR",
		198: "SYS_LREMOVEXATTR",
		199: "SYS_FREMOVEXATTR",
		200: "SYS_TKILL",
		201: "SYS_TIME",
		202: "SYS_FUTEX",
		203: "SYS_SCHED_SETAFFINITY",
		204: "SYS_SCHED_GETAFFINITY",
		205: "SYS_SET_THREAD_AREA",
		206: "SYS_IO_SETUP",
		207: "SYS_IO_DESTROY",
		208: "SYS_IO_GETEVENTS",
		209: "SYS_IO_SUBMIT",
		210: "SYS_IO_CANCEL",
		211: "SYS_GET_THREAD_AREA",
		212: "SYS_LOOKUP_DCOOKIE",
		213: "SYS_EPOLL_CREATE",
		214: "SYS_EPOLL_CTL_OLD",
		215: "SYS_EPOLL_WAIT_OLD",
		216: "SYS_REMAP_FILE_PAGES",
		217: "SYS_GETDENTS64",
		218: "SYS_SET_TID_ADDRESS",
		219: "SYS_RESTART_SYSCALL",
		220: "SYS_SEMTIMEDOP",
		221: "SYS_FADVISE64",
		222: "SYS_TIMER_CREATE",
		223: "SYS_TIMER_SETTIME",
		224: "SYS_TIMER_GETTIME",
		225: "SYS_TIMER_GETOVERRUN",
		226: "SYS_TIMER_DELETE",
		227: "SYS_CLOCK_SETTIME",
		228: "SYS_CLOCK_GETTIME",
		229: "SYS_CLOCK_GETRES",
		230: "SYS_CLOCK_NANOSLEEP",
		231: "SYS_EXIT_GROUP",
		232: "SYS_EPOLL_WAIT",
		233: "SYS_EPOLL_CTL",
		234: "SYS_TGKILL",
		235: "SYS_UTIMES",
		236: "SYS_VSERVER",
		237: "SYS_MBIND",
		238: "SYS_SET_MEMPOLICY",
		239: "SYS_GET_MEMPOLICY",
		240: "SYS_MQ_OPEN",
		241: "SYS_MQ_UNLINK",
		242: "SYS_MQ_TIMEDSEND",
		243: "SYS_MQ_TIMEDRECEIVE",
		244: "SYS_MQ_NOTIFY",
		245: "SYS_MQ_GETSETATTR",
		246: "SYS_KEXEC_LOAD",
		247: "SYS_WAITID",
		248: "SYS_ADD_KEY",
		249: "SYS_REQUEST_KEY",
		250: "SYS_KEYCTL",
		251: "SYS_IOPRIO_SET",
		252: "SYS_IOPRIO_GET",
		253: "SYS_INOTIFY_INIT",
		254: "SYS_INOTIFY_ADD_WATCH",
		255: "SYS_INOTIFY_RM_WATCH",
		256: "SYS_MIGRATE_PAGES",
		257: "SYS_OPENAT",
		258: "SYS_MKDIRAT",
		259: "SYS_MKNODAT",
		260: "SYS_FCHOWNAT",
		261: "SYS_FUTIMESAT",
		262: "SYS_NEWFSTATAT",
		263: "SYS_UNLINKAT",
		264: "SYS_RENAMEAT",
		265: "SYS_LINKAT",
		266: "SYS_SYMLINKAT",
		267: "SYS_READLINKAT",
		268: "SYS_FCHMODAT",
		269: "SYS_FACCESSAT",
		270: "SYS_PSELECT6",
		271: "SYS_PPOLL",
		272: "SYS_UNSHARE",
		273: "SYS_SET_ROBUST_LIST",
		274: "SYS_GET_ROBUST_LIST",
		275: "SYS_SPLICE",
		276: "SYS_TEE",
		277: "SYS_SYNC_FILE_RANGE",
		278: "SYS_VMSPLICE",
		279: "SYS_MOVE_PAGES",
		280: "SYS_UTIMENSAT",
		281: "SYS_EPOLL_PWAIT",
		282: "SYS_SIGNALFD",
		283: "SYS_TIMERFD_CREATE",
		284: "SYS_EVENTFD",
		285: "SYS_FALLOCATE",
		286: "SYS_TIMERFD_SETTIME",
		287: "SYS_TIMERFD_GETTIME",
		288: "SYS_ACCEPT4",
		289: "SYS_SIGNALFD4",
		290: "SYS_EVENTFD2",
		291: "SYS_EPOLL_CREATE1",
		292: "SYS_DUP3",
		293: "SYS_PIPE2",
		294: "SYS_INOTIFY_INIT1",
		295: "SYS_PREADV",
		296: "SYS_PWRITEV",
		297: "SYS_RT_TGSIGQUEUEINFO",
		298: "SYS_PERF_EVENT_OPEN",
		299: "SYS_RECVMMSG",
		300: "SYS_FANOTIFY_INIT",
		301: "SYS_FANOTIFY_MARK",
		302: "SYS_PRLIMIT64",
		303: "SYS_NAME_TO_HANDLE_AT",
		304: "SYS_OPEN_BY_HANDLE_AT",
		305: "SYS_CLOCK_ADJTIME",
		306: "SYS_SYNCFS",
		307: "SYS_SENDMMSG",
		308: "SYS_SETNS",
		309: "SYS_GETCPU",
		310: "SYS_PROCESS_VM_READV",
		311: "SYS_PROCESS_VM_WRITEV",
		312: "SYS_KCMP",
		313: "SYS_FINIT_MODULE",
		314: "SYS_SCHED_SETATTR",
		315: "SYS_SCHED_GETATTR",
		316: "SYS_RENAMEAT2",
		317: "SYS_SECCOMP",
		318: "SYS_GETRANDOM",
		319: "SYS_MEMFD_CREATE",
		320: "SYS_KEXEC_FILE_LOAD",
		321: "SYS_BPF",
		322: "SYS_EXECVEAT",
		323: "SYS_USERFAULTFD",
		324: "SYS_MEMBARRIER",
		325: "SYS_MLOCK2",
		326: "SYS_COPY_FILE_RANGE",
		327: "SYS_PREADV2",
		328: "SYS_PWRITEV2",
		329: "SYS_PKEY_MPROTECT",
		330: "SYS_PKEY_ALLOC",
		331: "SYS_PKEY_FREE",
		332: "SYS_STATX",

		351: "DO_EXIT",
		352: "CAP_CAPABLE",
	}

	var res string

	if syscallName, ok := syscalls[sc]; ok {
		res = syscallName
	} else {
		res = strconv.Itoa(int(sc))
	}

	return res
}

// getErrorMessage Function
func getErrorMessage(errno int64) string {
	// errno -l

	var errMsg = map[int64]string{
		1:   "Operation not permitted",
		2:   "No such file or directory",
		3:   "No such process",
		4:   "Interrupted system call",
		5:   "Input/output error",
		6:   "No such device or address",
		7:   "Argument list too long",
		8:   "Exec format error",
		9:   "Bad file descriptor",
		10:  "No child processes",
		11:  "Resource temporarily unavailable",
		12:  "Cannot allocate memory",
		13:  "Permission denied",
		14:  "Bad address",
		15:  "Block device required",
		16:  "Device or resource busy",
		17:  "File exists",
		18:  "Invalid cross-device link",
		19:  "No such device",
		20:  "Not a directory",
		21:  "Is a directory",
		22:  "Invalid argument",
		23:  "Too many open files in system",
		24:  "Too many open files",
		25:  "Inappropriate ioctl for device",
		26:  "Text file busy",
		27:  "File too large",
		28:  "No space left on device",
		29:  "Illegal seek",
		30:  "Read-only file system",
		31:  "Too many links",
		32:  "Broken pipe",
		33:  "Numerical argument out of domain",
		34:  "Numerical result out of range",
		35:  "Resource deadlock avoided",
		36:  "File name too long",
		37:  "No locks available",
		38:  "Function not implemented",
		39:  "Directory not empty",
		40:  "Too many levels of symbolic links",
		42:  "No message of desired type",
		43:  "Identifier removed",
		44:  "Channel number out of range",
		45:  "Level 2 not synchronized",
		46:  "Level 3 halted",
		47:  "Level 3 reset",
		48:  "Link number out of range",
		49:  "Protocol driver not attached",
		50:  "No CSI structure available",
		51:  "Level 2 halted",
		52:  "Invalid exchange",
		53:  "Invalid request descriptor",
		54:  "Exchange full",
		55:  "No anode",
		56:  "Invalid request code",
		57:  "Invalid slot",
		59:  "Bad font file format",
		60:  "Device not a stream",
		61:  "No data available",
		62:  "Timer expired",
		63:  "Out of streams resources",
		64:  "Machine is not on the network",
		65:  "Package not installed",
		66:  "Object is remote",
		67:  "Link has been severed",
		68:  "Advertise error",
		69:  "Srmount error",
		70:  "Communication error on send",
		71:  "Protocol error",
		72:  "Multihop attempted",
		73:  "RFS specific error",
		74:  "Bad message",
		75:  "Value too large for defined data type",
		76:  "Name not unique on network",
		77:  "File descriptor in bad state",
		78:  "Remote address changed",
		79:  "Can not access a needed shared library",
		80:  "Accessing a corrupted shared library",
		81:  ".lib section in a.out corrupted",
		82:  "Attempting to link in too many shared libraries",
		83:  "Cannot exec a shared library directly",
		84:  "Invalid or incomplete multibyte or wide character",
		85:  "Interrupted system call should be restarted",
		86:  "Streams pipe error",
		87:  "Too many users",
		88:  "Socket operation on non-socket",
		89:  "Destination address required",
		90:  "Message too long",
		91:  "Protocol wrong type for socket",
		92:  "Protocol not available",
		93:  "Protocol not supported",
		94:  "Socket type not supported",
		95:  "Operation not supported",
		96:  "Protocol family not supported",
		97:  "Address family not supported by protocol",
		98:  "Address already in use",
		99:  "Cannot assign requested address",
		100: "Network is down",
		101: "Network is unreachable",
		102: "Network dropped connection on reset",
		103: "Software caused connection abort",
		104: "Connection reset by peer",
		105: "No buffer space available",
		106: "Transport endpoint is already connected",
		107: "Transport endpoint is not connected",
		108: "Cannot send after transport endpoint shutdown",
		109: "Too many references: cannot splice",
		110: "Connection timed out",
		111: "Connection refused",
		112: "Host is down",
		113: "No route to host",
		114: "Operation already in progress",
		115: "Operation now in progress",
		116: "Stale file handle",
		117: "Structure needs cleaning",
		118: "Not a XENIX named type file",
		119: "No XENIX semaphores available",
		120: "Is a named type file",
		121: "Remote I/O error",
		122: "Disk quota exceeded",
		123: "No medium found",
		124: "Wrong medium type",
		125: "Operation canceled",
		126: "Required key not available",
		127: "Key has expired",
		128: "Key has been revoked",
		129: "Key was rejected by service",
		130: "Owner died",
		131: "State not recoverable",
		132: "Operation not possible due to RF-kill",
		133: "Memory page has hardware error",
	}

	var res string

	if msg, ok := errMsg[-errno]; ok {
		res = msg
	} else {
		res = "Unknown error"
	}

	return res
}

// readArgTypeFromBuff Function
func readArgTypeFromBuff(buff io.Reader) (uint8, error) {
	var res uint8
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

// readArgFromBuff Function
func readArgFromBuff(dataBuff io.Reader) (interface{}, error) {
	var err error
	var res interface{}

	at, err := readArgTypeFromBuff(dataBuff)
	if err != nil {
		return res, fmt.Errorf("error reading arg type: %v", err)
	}

	switch at {
	case intT:
		res, err = readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case strT:
		res, err = readStringFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case strArrT:
		var ss []string
		et, err := readArgTypeFromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading string array element type: %v", err)
		}
		for et != strArrT {
			s, err := readStringFromBuff(dataBuff)
			if err != nil {
				return nil, fmt.Errorf("error reading string element: %v", err)
			}
			ss = append(ss, s)

			et, err = readArgTypeFromBuff(dataBuff)
			if err != nil {
				return nil, fmt.Errorf("error reading string array element type: %v", err)
			}
		}
		res = ss
	case capT:
		cap, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading capability arg: %v", err)
		}
		res = getCapabilityName(cap)
	case syscallT:
		sc, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading syscall arg: %v", err)
		}
		res = getSyscallName(sc)
	case sockAddrT:
		sockaddr, err := readSockaddrFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = sockaddr
	case openFlagsT:
		flags, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getOpenFlags(flags)
	case execFlagsT:
		flags, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getExecFlags(flags)
	case sockDomT:
		dom, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getSocketDomain(dom)
	case sockTypeT:
		t, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getSocketType(t)
	default:
		return nil, fmt.Errorf("error unknown arg type %v", at)
	}

	return res, nil
}

// GetArgs Function
func GetArgs(dataBuff *bytes.Buffer, Argnum int32) ([]interface{}, error) {
	args := []interface{}{}

	for i := 0; i < int(Argnum); i++ {
		arg, err := readArgFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
	}

	return args, nil
}
