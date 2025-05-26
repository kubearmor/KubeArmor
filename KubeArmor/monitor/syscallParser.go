// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

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

	"golang.org/x/sys/unix"
)

// ===================== //
// == Const. Vaiables == //
// ===================== //

// Data Types
const (
	intT          uint8 = 1
	strT          uint8 = 10
	strArrT       uint8 = 11
	sockAddrT     uint8 = 12
	openFlagsT    uint8 = 13
	execFlagsT    uint8 = 14
	sockDomT      uint8 = 15
	sockTypeT     uint8 = 16
	capT          uint8 = 17
	syscallT      uint8 = 18
	unlinkAtFlagT uint8 = 19
	ptraceReqT    uint8 = 23
	mountFlagT    uint8 = 24
	umountFlagT   uint8 = 25
	udpMsg        uint8 = 26
	qtype         uint8 = 27
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

// Min Function
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// readByteSliceFromBuff Function
func readByteSliceFromBuff(buff io.Reader, len int) ([]byte, error) {
	res := []byte{}
	if len > 0 {
		res = make([]byte, Min(len, MaxStringLen))
		if err := binary.Read(buff, binary.LittleEndian, &res); err != nil {
			return nil, fmt.Errorf("error reading byte array: %v", err)
		}
		return res, nil
	}
	return nil, fmt.Errorf("error reading byte array: invalid len")
}

// readStringFromBuff Function
func readStringFromBuff(buff io.Reader) (string, error) {
	var err error
	size, err := readInt32FromBuff(buff)
	if err != nil {
		return "", fmt.Errorf("error reading string size: %v", err)
	}
	if size == 0 {
		// empty string
		return "", nil
	}
	res, err := readByteSliceFromBuff(buff, int(size-1)) // last byte is string terminating null
	defer func() {
		_, _ = readInt8FromBuff(buff) // discard last byte which is string terminating null
	}()
	if err != nil {
		return "", fmt.Errorf("error reading string: %v", err)
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

		// https://elixir.bootlin.com/linux/v4.15/source/include/uapi/linux/in.h#L238
		// Discard sin_zero (8 bytes padding)
		_, err = readByteSliceFromBuff(buff, 8)
		if err != nil {
			return nil, fmt.Errorf("error skipping sin_zero padding: %v", err)
		}
	case 10: // AF_INET6
		// https://man7.org/linux/man-pages/man7/ipv6.7.html
		port, err := readUInt16BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}

		res["sin_port"] = strconv.Itoa(int(port))
		_, err = readUInt32BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing IPv6 flow information: %v", err)
		}
		addr, err := readByteSliceFromBuff(buff, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing IPv6 IP: %v", err)
		}
		ipv6 := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		n := copy(ipv6, addr)
		if n != 16 {
			return nil, fmt.Errorf("error Converting bytes to IPv6, copied only %d bytes out of 16", n)
		}
		res["sin_addr"] = ipv6.String()
	}
	return res, nil
}

// getUnlinkAtFlag Function
func getUnlinkAtFlag(flag uint32) string {
	var f = ""

	if flag == 0x200 {
		f = "AT_REMOVEDIR"
	}

	return f
}

// getPtraceReq
func getPtraceReq(req uint32) string {
	switch req {
	case 0:
		return "PTRACE_TRACEME"
	case 1:
		return "PTRACE_PEEKTEXT"
	case 2:
		return "PTRACE_PEEKDATA"
	case 3:
		return "PTRACE_PEEKUSER"
	case 4:
		return "PTRACE_POKETEXT"
	case 5:
		return "PTRACE_POKEDATA"
	case 6:
		return "PTRACE_POKEUSER"
	case 7:
		return "PTRACE_CONT"
	case 8:
		return "PTRACE_KILL"
	case 9:
		return "PTRACE_SINGLESTEP"
	case 12:
		return "PTRACE_GETREGS"
	case 13:
		return "PTRACE_SETREGS"
	case 14:
		return "PTRACE_GETFPREGS"
	case 15:
		return "PTRACE_SETFPREGS"
	case 16:
		return "PTRACE_ATTACH"
	case 17:
		return "PTRACE_DETACH"
	case 18:
		return "PTRACE_GETFPXREGS"
	case 19:
		return "PTRACE_SETFPXREGS"
	case 24:
		return "PTRACE_SYSCALL"
	case 0x4200:
		return "PTRACE_SETOPTIONS"
	case 0x4201:
		return "PTRACE_GETEVENTMSG"
	case 0x4202:
		return "PTRACE_GETSIGINFO"
	case 0x4203:
		return "PTRACE_SETSIGINFO"
	case 0x4204:
		return "PTRACE_GETREGSET"
	case 0x4205:
		return "PTRACE_SETREGSET"
	case 0x4206:
		return "PTRACE_SEIZE"
	case 0x4207:
		return "PTRACE_INTERRUPT"
	case 0x4208:
		return "PTRACE_LISTEN"
	case 0x4209:
		return "PTRACE_PEEKSIGINFO"
	case 0x420a:
		return "PTRACE_GETSIGMASK"
	case 0x420b:
		return "PTRACE_SETSIGMASK"
	case 0x420c:
		return "PTRACE_SECCOMP_GET_FILTER"
	case 0x420d:
		return "PTRACE_SECCOMP_GET_METADATA"
	case 0x420e:
		return "PTRACE_GET_SYSCALL_INFO"
	default:
		return strconv.Itoa(int(req))
	}
}

// getMountFlags Function
func getMountFlags(flag uint32) string {
	switch flag {
	case 1:
		return "MS_RDONLY"
	case 2:
		return "MS_NOSUID"
	case 4:
		return "MS_NODEV"
	case 8:
		return "MS_NOEXEC"
	case 16:
		return "MS_SYNCHRONOUS"
	case 32:
		return "MS_REMOUNT"
	case 64:
		return "MS_MANDLOCK"
	case 128:
		return "S_WRITE"
	case 256:
		return "S_APPEND"
	case 512:
		return "S_IMMUTABLE"
	case 1024:
		return "MS_NOATIME"
	case 2048:
		return "MS_NODIRATIME"
	case 4096:
		return "MS_BIND"
	default:
		return strconv.Itoa(int(flag))
	}
}

// getUmountFlags Function
func getUmountFlags(flag uint32) string {
	switch flag {
	case 1:
		return "MNT_FORCE"
	case 2:
		return "MNT_DETACH"
	case 4:
		return "MNT_EXPIRE"
	case 8:
		return "UMOUNT_NOFOLLOW"
	default:
		return strconv.Itoa(int(flag))
	}
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

// getSocketDomain Function
func getSocketDomain(sd uint32) string {
	// readSocketDomain prints the `domain` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html

	var res string

	if sdName, ok := socketDomains[sd]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(sd))
	}

	return res
}

var socketTypes = map[uint32]string{
	1:  "SOCK_STREAM",
	2:  "SOCK_DGRAM",
	3:  "SOCK_RAW",
	4:  "SOCK_RDM",
	5:  "SOCK_SEQPACKET",
	6:  "SOCK_DCCP",
	10: "SOCK_PACKET",
}

// GetSocketType Function
func GetSocketType(st uint32) string {
	// readSocketType prints the `type` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html
	// https://elixir.bootlin.com/linux/v5.5.3/source/arch/mips/include/asm/socket.h

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

var protocols = map[int32]string{
	0:   "HOPOPT",
	1:   "ICMP",
	2:   "IGMP",
	3:   "GGP",
	4:   "IPv4",
	5:   "ST",
	6:   "TCP",
	7:   "CBT",
	8:   "EGP",
	9:   "IGP",
	10:  "BBN-RCC-MON",
	11:  "NVP-II",
	12:  "PUP",
	14:  "EMCON",
	15:  "XNET",
	16:  "CHAOS",
	17:  "UDP",
	18:  "MUX",
	19:  "DCN-MEAS",
	20:  "HMP",
	21:  "PRM",
	22:  "XNS-IDP",
	23:  "TRUNK-1",
	24:  "TRUNK-2",
	25:  "LEAF-1",
	26:  "LEAF-2",
	27:  "RDP",
	28:  "IRTP",
	29:  "ISO-TP4",
	30:  "NETBLT",
	31:  "MFE-NSP",
	32:  "MERIT-INP",
	33:  "DCCP",
	34:  "3PC",
	35:  "IDPR",
	36:  "XTP",
	37:  "DDP",
	38:  "IDPR-CMTP",
	39:  "TP++",
	40:  "IL",
	41:  "IPv6",
	42:  "SDRP",
	43:  "IPv6-Route",
	44:  "IPv6-Frag",
	45:  "IDRP",
	46:  "RSVP",
	47:  "GRE",
	48:  "DSR",
	49:  "BNA",
	50:  "ESP",
	51:  "AH",
	52:  "I-NLSP",
	54:  "NARP",
	55:  "Min-IPv4",
	56:  "TLSP",
	57:  "SKIP",
	58:  "IPv6-ICMP",
	59:  "IPv6-NoNxt",
	60:  "IPv6-Opts",
	62:  "CFTP",
	64:  "SAT-EXPAK",
	65:  "KRYPTOLAN",
	66:  "RVD",
	67:  "IPPC",
	69:  "SAT-MON",
	70:  "VISA",
	71:  "IPCV",
	72:  "CPNX",
	73:  "CPHB",
	74:  "WSN",
	75:  "PVP",
	76:  "BR-SAT-MON",
	77:  "SUN-ND",
	78:  "WB-MON",
	79:  "WB-EXPAK",
	80:  "ISO-IP",
	81:  "VMTP",
	82:  "SECURE-VMTP",
	83:  "VINES",
	84:  "IPTM",
	85:  "NSFNET-IGP",
	86:  "DGP",
	87:  "TCF",
	88:  "EIGRP",
	89:  "OSPF",
	90:  "Sprite-RPC",
	91:  "LARP",
	92:  "MTP",
	93:  "AX.25",
	94:  "IPIP",
	96:  "SCC-SP",
	97:  "ETHERIP",
	98:  "ENCAP",
	100: "GMTP",
	101: "IFMP",
	102: "PNNI",
	103: "PIM",
	104: "ARIS",
	105: "SCPS",
	106: "QNX",
	107: "A/N",
	108: "IPComp",
	109: "SNP",
	110: "Compaq-Peer",
	111: "IPX-in-IP",
	112: "VRRP",
	113: "PGM",
	115: "L2TP",
	116: "DDX",
	117: "IATP",
	118: "STP",
	119: "SRP",
	120: "UTI",
	121: "SMP",
	123: "PTP",
	125: "FIRE",
	126: "CRTP",
	127: "CRUDP",
	128: "SSCOPMCE",
	129: "IPLT",
	130: "SPS",
	131: "PIPE",
	132: "SCTP",
	133: "FC",
	134: "RSVP-E2E-IGNORE",
	136: "UDPLite",
	137: "MPLS-in-IP",
	138: "manet",
	139: "HIP",
	140: "Shim6",
	141: "WESP",
	142: "ROHC",
	143: "Ethernet",
	144: "AGGFRAG",
	145: "NSH",
	255: "Reserved",
}

// getProtocol Function
func GetProtocol(proto int32) string {
	var res string

	if protoName, ok := protocols[proto]; ok {
		res = protoName
	} else {
		res = strconv.Itoa(int(proto))
	}

	return res
}

// Capabilities code to name
var Capabilities = map[int32]string{
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
var CapToCode = map[string]uint8{
	"CAP_AUDIT_CONTROL":    unix.CAP_AUDIT_CONTROL,
	"CAP_AUDIT_READ":       unix.CAP_AUDIT_READ,
	"CAP_AUDIT_WRITE":      unix.CAP_AUDIT_WRITE,
	"CAP_DAC_READ_SEARCH":  unix.CAP_DAC_READ_SEARCH,
	"CAP_DAC_OVERRIDE":     unix.CAP_DAC_OVERRIDE,
	"CAP_LINUX_IMMUTABLE":  unix.CAP_LINUX_IMMUTABLE,
	"CAP_NET_BROADCAST":    unix.CAP_NET_BROADCAST,
	"CAP_NET_ADMIN":        unix.CAP_NET_ADMIN,
	"CAP_NET_BIND_SERVICE": unix.CAP_NET_BIND_SERVICE,
	"CAP_NET_RAW":          unix.CAP_NET_RAW,
	"CAP_IPC_LOCK":         unix.CAP_IPC_LOCK,
	"CAP_IPC_OWNER":        unix.CAP_IPC_OWNER,
	"CAP_SYS_MODULE":       unix.CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":        unix.CAP_SYS_RAWIO,
	"CAP_SYS_PTRACE":       unix.CAP_SYS_PTRACE,
	"CAP_SYS_PACCT":        unix.CAP_SYS_PACCT,
	"CAP_SYS_ADMIN":        unix.CAP_SYS_ADMIN,
	"CAP_SYS_BOOT":         unix.CAP_SYS_BOOT,
	"CAP_SYS_NICE":         unix.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":     unix.CAP_SYS_RESOURCE,
	"CAP_SYS_TIME":         unix.CAP_SYS_TIME,
	"CAP_SYS_TTY_CONFIG":   unix.CAP_SYS_TTY_CONFIG,
	"CAP_SYS_CHROOT":       unix.CAP_SYS_CHROOT,
	"CAP_SYSLOG":           unix.CAP_SYSLOG,
	"CAP_LEASE":            unix.CAP_LEASE,
	"CAP_MAC_OVERRIDE":     unix.CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":        unix.CAP_MAC_ADMIN,
	"CAP_WAKE_ALARM":       unix.CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":    unix.CAP_BLOCK_SUSPEND,
	"CAP_CHOWN":            unix.CAP_CHOWN,
	"CAP_FOWNER":           unix.CAP_FOWNER,
	"CAP_FSETID":           unix.CAP_FSETID,
	"CAP_KILL":             unix.CAP_KILL,
	"CAP_SETGID":           unix.CAP_SETGID,
	"CAP_SETUID":           unix.CAP_SETUID,
	"CAP_SETPCAP":          unix.CAP_SETPCAP,
	"CAP_PERFMON":          unix.CAP_PERFMON,
	"CAP_MKNOD":            unix.CAP_MKNOD,
	"CAP_SETFCAP":          unix.CAP_SETFCAP,
	"CAP_BPF":              unix.CAP_BPF,
}

// getCapabilityName Function
func getCapabilityName(cap int32) string {
	// getCapabilityName prints the `capability` bitmask argument of the `cap_capable` function
	// include/uapi/linux/capability.h

	var res string

	if capName, ok := Capabilities[cap]; ok {
		res = capName
	} else {
		res = strconv.Itoa(int(cap))
	}

	return res
}

// GetSyscallName Function
func GetSyscallName(sc int32) string {
	// source: /usr/include/x86_64-linux-gnu/asm/unistd_64.h

	var res string

	if syscallName, ok := syscalls[sc]; ok {
		res = syscallName
	} else {
		res = strconv.Itoa(int(sc))
	}

	return res
}

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

// getErrorMessage Function
func getErrorMessage(errno int64) string {
	// errno -l

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
		return res, fmt.Errorf("error reading argument type: %v", err)
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
			return nil, fmt.Errorf("error reading capability type: %v", err)
		}
		res = getCapabilityName(cap)
	case syscallT:
		sc, err := readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading syscall type: %v", err)
		}
		res = GetSyscallName(sc)
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
	case unlinkAtFlagT:
		flag, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getUnlinkAtFlag(flag)
	case execFlagsT:
		flags, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getExecFlags(flags)
	case ptraceReqT:
		req, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getPtraceReq(req)
	case mountFlagT:
		req, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getMountFlags(req)
	case umountFlagT:
		req, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getUmountFlags(req)
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
		res = GetSocketType(t)
	case udpMsg:
		res, err = readStringFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case qtype:
		res, err = readUInt16BigendFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("error unknown argument type %v", at)
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

var auditedSyscalls = map[int]string{
	84:  "rmdir",
	87:  "unlink",
	92:  "chown",
	105: "setuid",
	106: "setgid",
	260: "fchownat",
	263: "unlinkat",
	101: "ptrace",
	165: "mount",
	166: "umount",
}

func isAuditedSyscall(syscallID int32) bool {
	if _, ok := auditedSyscalls[int(syscallID)]; ok {
		return true
	}
	return false
}
