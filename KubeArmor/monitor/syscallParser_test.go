// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package monitor

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"
)

// Helper to write a string in the format expected by readStringFromBuff
func writeMockString(buf *bytes.Buffer, s string) {
	// Format: size (int32) = len(s) + 1 (for null terminator)
	// then bytes of s, then null terminator (byte 0)
	size := int32(len(s) + 1)
	_ = binary.Write(buf, binary.LittleEndian, size)
	buf.WriteString(s)
	buf.WriteByte(0)
}

func TestReadContextFromBuff(t *testing.T) {
	expected := SyscallContext{
		Ts:       123456789,
		PidID:    100,
		MntID:    200,
		HostPPID: 1,
		HostPID:  2,
		PPID:     3,
		PID:      4,
		UID:      1000,
		EventID:  5,
		Argnum:   2,
		Retval:   0,
		OID:      99,
		ExecID:   12,
		Hash:     1,
	}
	copy(expected.Comm[:], "test_comm")
	copy(expected.Cwd[:], "/test/cwd")
	copy(expected.TTY[:], "/dev/pts/0")

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, &expected)
	if err != nil {
		t.Fatalf("failed to write mock context: %v", err)
	}

	// 1. Success case
	bufBytes := buf.Bytes()
	actual, err := readContextFromBuff(&buf)
	if err != nil {
		t.Fatalf("readContextFromBuff failed: %v", err)
	}

	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("expected %+v, got %+v", expected, actual)
	}

	// 2. Truncated case
	truncatedBuf := bytes.NewReader(bufBytes[:20])
	_, err = readContextFromBuff(truncatedBuf)
	if err == nil {
		t.Error("expected error for truncated buffer, got nil")
	}
}

func TestReadArgFromBuff(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*bytes.Buffer)
		expected any
		wantErr  bool
	}{
		{
			name: "intT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(intT)
				_ = binary.Write(b, binary.LittleEndian, int32(42))
			},
			expected: int32(42),
		},
		{
			name: "strT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(strT)
				writeMockString(b, "hello")
			},
			expected: "hello",
		},
		{
			name: "strT empty",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(strT)
				_ = binary.Write(b, binary.LittleEndian, int32(0))
			},
			expected: "",
		},
		{
			name: "strArrT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(strArrT)
				// write element type (strT) and string
				b.WriteByte(strT)
				writeMockString(b, "first")
				b.WriteByte(strT)
				writeMockString(b, "second")
				// terminate array with strArrT
				b.WriteByte(strArrT)
			},
			expected: []string{"first", "second"},
		},
		{
			name: "capT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(capT)
				_ = binary.Write(b, binary.LittleEndian, int32(1)) // CAP_DAC_OVERRIDE
			},
			expected: "CAP_DAC_OVERRIDE",
		},
		{
			name: "syscallT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(syscallT)
				_ = binary.Write(b, binary.LittleEndian, int32(84)) // rmdir
			},
			expected: GetSyscallName(84),
		},
		{
			name: "sockAddrT AF_UNIX",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(sockAddrT)
				_ = binary.Write(b, binary.LittleEndian, int16(1)) // AF_UNIX
				var path [108]byte
				copy(path[:], "/tmp/socket")
				_ = binary.Write(b, binary.LittleEndian, path)
			},
			expected: map[string]string{
				"sa_family": "AF_UNIX",
				"sun_path":  "/tmp/socket",
			},
		},
		{
			name: "sockAddrT AF_INET",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(sockAddrT)
				_ = binary.Write(b, binary.LittleEndian, int16(2))            // AF_INET
				_ = binary.Write(b, binary.BigEndian, uint16(8080))           // Port
				_ = binary.Write(b, binary.BigEndian, uint32(0x7f000001))     // 127.0.0.1
				_ = binary.Write(b, binary.LittleEndian, [8]byte{0, 0, 0, 0}) // Padding
			},
			expected: map[string]string{
				"sa_family": "AF_INET",
				"sin_port":  "8080",
				"sin_addr":  "127.0.0.1",
			},
		},
		{
			name: "sockAddrT AF_INET6",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(sockAddrT)
				_ = binary.Write(b, binary.LittleEndian, int16(10)) // AF_INET6
				_ = binary.Write(b, binary.BigEndian, uint16(9090)) // Port
				_ = binary.Write(b, binary.BigEndian, uint32(0))    // Flow info
				var ip [16]byte
				copy(ip[:], net.ParseIP("2001:db8::1"))
				_ = binary.Write(b, binary.LittleEndian, ip)
			},
			expected: map[string]string{
				"sa_family": "AF_INET6",
				"sin_port":  "9090",
				"sin_addr":  "2001:db8::1",
			},
		},
		{
			name: "openFlagsT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(openFlagsT)
				_ = binary.Write(b, binary.LittleEndian, uint32(0x2)) // O_RDWR
			},
			expected: "O_RDWR",
		},
		{
			name: "unlinkAtFlagT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(unlinkAtFlagT)
				_ = binary.Write(b, binary.LittleEndian, uint32(0x200)) // AT_REMOVEDIR
			},
			expected: "AT_REMOVEDIR",
		},
		{
			name: "execFlagsT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(execFlagsT)
				_ = binary.Write(b, binary.LittleEndian, uint32(0x100)) // AT_EMPTY_PATH
			},
			expected: "AT_EMPTY_PATH",
		},
		{
			name: "ptraceReqT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(ptraceReqT)
				_ = binary.Write(b, binary.LittleEndian, uint32(16)) // PTRACE_ATTACH
			},
			expected: "PTRACE_ATTACH",
		},
		{
			name: "mountFlagT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(mountFlagT)
				_ = binary.Write(b, binary.LittleEndian, uint32(1)) // MS_RDONLY
			},
			expected: "MS_RDONLY",
		},
		{
			name: "umountFlagT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(umountFlagT)
				_ = binary.Write(b, binary.LittleEndian, uint32(1)) // MNT_FORCE
			},
			expected: "MNT_FORCE",
		},
		{
			name: "sockDomT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(sockDomT)
				_ = binary.Write(b, binary.LittleEndian, uint32(2)) // AF_INET
			},
			expected: "AF_INET",
		},
		{
			name: "sockTypeT",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(sockTypeT)
				_ = binary.Write(b, binary.LittleEndian, uint32(1)) // SOCK_STREAM
			},
			expected: "SOCK_STREAM",
		},
		{
			name: "udpMsg",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(udpMsg)
				writeMockString(b, "udp_payload")
			},
			expected: "udp_payload",
		},
		{
			name: "qtype",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(qtype)
				_ = binary.Write(b, binary.BigEndian, uint16(5))
			},
			expected: uint16(5),
		},
		{
			name: "unknown argument type",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(99)
			},
			wantErr: true,
		},
		{
			name: "truncated type",
			setup: func(b *bytes.Buffer) {
				// empty buffer
			},
			wantErr: true,
		},
		{
			name: "truncated int data",
			setup: func(b *bytes.Buffer) {
				b.WriteByte(intT)
				b.WriteByte(1) // only 1 byte of int32
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tt.setup(&buf)

			res, err := readArgFromBuff(&buf)
			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error result: %v", err)
			}
			if !tt.wantErr && !reflect.DeepEqual(res, tt.expected) {
				t.Errorf("expected %+v, got %+v", tt.expected, res)
			}
		})
	}
}

func TestGetHashes(t *testing.T) {
	// 1. Success case with multiple hashes
	var buf bytes.Buffer
	buf.WriteByte(3) // numOfHashes = 3

	// Hash 1: ProcessHash (Type 30)
	_ = binary.Write(&buf, binary.LittleEndian, int32(30))
	var h1 [32]byte
	copy(h1[:], "processhashprocesshashprocesshas")
	buf.Write(h1[:])

	// Hash 2: ParentHash (Type 31)
	_ = binary.Write(&buf, binary.LittleEndian, int32(31))
	var h2 [32]byte
	copy(h2[:], "parenthashparenthashparenthashpa")
	buf.Write(h2[:])

	// Hash 3: ResourceHash (Type 32)
	_ = binary.Write(&buf, binary.LittleEndian, int32(32))
	var h3 [32]byte
	copy(h3[:], "resourcehashresourcehashresource")
	buf.Write(h3[:])

	res, err := GetHashes(&buf)
	if err != nil {
		t.Fatalf("GetHashes failed: %v", err)
	}

	expected := HashContext{
		ProcessHash:  "70726f636573736861736870726f636573736861736870726f63657373686173", // hex encoded
		ParentHash:   "706172656e7468617368706172656e7468617368706172656e74686173687061",
		ResourceHash: "7265736f75726365686173687265736f75726365686173687265736f75726365",
		HashAlgo:     1,
	}

	if !reflect.DeepEqual(res, expected) {
		t.Errorf("expected %+v, got %+v", expected, res)
	}

	// 2. Truncated case
	var bufTruncated bytes.Buffer
	bufTruncated.WriteByte(1)
	_ = binary.Write(&bufTruncated, binary.LittleEndian, int32(30))
	bufTruncated.Write([]byte{1, 2, 3}) // incomplete hash

	_, err = GetHashes(&bufTruncated)
	if err == nil {
		t.Error("expected error for truncated hash data, got nil")
	}

	// 3. Unknown hash type
	var bufUnknown bytes.Buffer
	bufUnknown.WriteByte(1)
	_ = binary.Write(&bufUnknown, binary.LittleEndian, int32(99)) // unknown hash type
	bufUnknown.Write(h1[:])

	_, err = GetHashes(&bufUnknown)
	if err == nil {
		t.Error("expected error for unknown hash type, got nil")
	}
}

func TestGetArgs(t *testing.T) {
	// 1. Success case with two arguments
	var buf bytes.Buffer
	// Arg 1: intT (42)
	buf.WriteByte(intT)
	_ = binary.Write(&buf, binary.LittleEndian, int32(42))
	// Arg 2: strT ("test")
	buf.WriteByte(strT)
	writeMockString(&buf, "test")

	res, err := GetArgs(&buf, 2)
	if err != nil {
		t.Fatalf("GetArgs failed: %v", err)
	}

	expected := []any{int32(42), "test"}
	if !reflect.DeepEqual(res, expected) {
		t.Errorf("expected %+v, got %+v", expected, res)
	}

	// 2. Truncated case
	var bufTruncated bytes.Buffer
	bufTruncated.WriteByte(intT)

	_, err = GetArgs(&bufTruncated, 1)
	if err == nil {
		t.Error("expected error for truncated argument, got nil")
	}
}

func TestHelperMappings(t *testing.T) {
	// Test getUnlinkAtFlag
	if getUnlinkAtFlag(0x200) != "AT_REMOVEDIR" {
		t.Errorf("invalid unlinkat flag")
	}
	if getUnlinkAtFlag(0) != "" {
		t.Errorf("invalid unlinkat flag default")
	}

	// Test getPtraceReq
	if getPtraceReq(16) != "PTRACE_ATTACH" {
		t.Errorf("invalid ptrace req")
	}
	if getPtraceReq(9999) != "9999" {
		t.Errorf("invalid ptrace req default")
	}

	// Test getMountFlags
	if getMountFlags(1) != "MS_RDONLY" {
		t.Errorf("invalid mount flag")
	}
	if getMountFlags(999) != "999" {
		t.Errorf("invalid mount flag default")
	}

	// Test getUmountFlags
	if getUmountFlags(1) != "MNT_FORCE" {
		t.Errorf("invalid umount flag")
	}
	if getUmountFlags(999) != "999" {
		t.Errorf("invalid umount flag default")
	}

	// Test getOpenFlags
	if getOpenFlags(0) != "O_RDONLY" {
		t.Errorf("invalid open flags default")
	}
	if getOpenFlags(01) != "O_WRONLY" {
		t.Errorf("invalid open flags write only")
	}

	// Test getExecFlags
	if getExecFlags(0x100) != "AT_EMPTY_PATH" {
		t.Errorf("invalid exec flags")
	}
	if getExecFlags(0) != "0" {
		t.Errorf("invalid exec flags default")
	}

	// Test getSocketDomain
	if getSocketDomain(2) != "AF_INET" {
		t.Errorf("invalid socket domain")
	}
	if getSocketDomain(999) != "999" {
		t.Errorf("invalid socket domain default")
	}

	// Test GetSocketType
	if GetSocketType(1) != "SOCK_STREAM" {
		t.Errorf("invalid socket type")
	}
	if GetSocketType(1|000004000) != "SOCK_STREAM|SOCK_NONBLOCK" {
		t.Errorf("invalid socket type flags")
	}

	// Test GetProtocol
	if GetProtocol(6) != "TCP" {
		t.Errorf("invalid protocol")
	}
	if GetProtocol(999) != "999" {
		t.Errorf("invalid protocol default")
	}

	// Test GetUSBResource
	if GetUSBResource(3, 1, 2, 4) != "USB HID_1_2 4" {
		t.Errorf("invalid USB resource mapping: %s", GetUSBResource(3, 1, 2, 4))
	}

	// Test getCapabilityName
	if getCapabilityName(21) != "CAP_SYS_ADMIN" {
		t.Errorf("invalid capability name")
	}
	if getCapabilityName(999) != "999" {
		t.Errorf("invalid capability name default")
	}

	// Test GetSyscallName
	scName := GetSyscallName(84)
	if scName != "SYS_RMDIR" && scName != "SYS_SYNC_FILE_RANGE" {
		t.Errorf("invalid syscall name: %s", scName)
	}
	if GetSyscallName(999) != "999" {
		t.Errorf("invalid syscall name default")
	}

	// Test getErrorMessage
	if getErrorMessage(-13) != "Permission denied" {
		t.Errorf("invalid error message: %s", getErrorMessage(-13))
	}
	if getErrorMessage(999) != "Unknown error" {
		t.Errorf("invalid error message default")
	}

	// Test isAuditedSyscall
	if !isAuditedSyscall(84) {
		t.Errorf("expected audited syscall")
	}
	if isAuditedSyscall(999) {
		t.Errorf("expected non-audited syscall")
	}
}

// Fuzzing Targets for Native Go Fuzzing

func FuzzReadContextFromBuff(f *testing.F) {
	var ctx SyscallContext
	ctx.Ts = 123456789
	ctx.PidID = 100
	ctx.MntID = 200
	ctx.EventID = 84
	ctx.Argnum = 2
	copy(ctx.Comm[:], "test_comm")

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, &ctx)
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = readContextFromBuff(r)
	})
}

func FuzzReadArgFromBuff(f *testing.F) {
	// Seed 1: intT
	var buf1 bytes.Buffer
	buf1.WriteByte(intT)
	_ = binary.Write(&buf1, binary.LittleEndian, int32(42))
	f.Add(buf1.Bytes())

	// Seed 2: strT
	var buf2 bytes.Buffer
	buf2.WriteByte(strT)
	writeMockString(&buf2, "fuzz_str")
	f.Add(buf2.Bytes())

	// Seed 3: strArrT
	var buf3 bytes.Buffer
	buf3.WriteByte(strArrT)
	buf3.WriteByte(strT)
	writeMockString(&buf3, "a")
	buf3.WriteByte(strArrT)
	f.Add(buf3.Bytes())

	// Seed 4: sockAddrT AF_INET
	var buf4 bytes.Buffer
	buf4.WriteByte(sockAddrT)
	_ = binary.Write(&buf4, binary.LittleEndian, int16(2))            // AF_INET
	_ = binary.Write(&buf4, binary.BigEndian, uint16(8080))           // Port
	_ = binary.Write(&buf4, binary.BigEndian, uint32(0x7f000001))     // IP
	_ = binary.Write(&buf4, binary.LittleEndian, [8]byte{0, 0, 0, 0}) // Padding
	f.Add(buf4.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = readArgFromBuff(r)
	})
}

func FuzzGetHashes(f *testing.F) {
	var buf bytes.Buffer
	buf.WriteByte(1)
	_ = binary.Write(&buf, binary.LittleEndian, int32(30))
	var h [32]byte
	copy(h[:], "somehashdatahere")
	buf.Write(h[:])
	f.Add(buf.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewBuffer(data)
		_, _ = GetHashes(r)
	})
}

func FuzzGetArgs(f *testing.F) {
	var buf bytes.Buffer
	buf.WriteByte(intT)
	_ = binary.Write(&buf, binary.LittleEndian, int32(100))
	f.Add(buf.Bytes(), int32(1))

	f.Fuzz(func(t *testing.T, data []byte, argNum int32) {
		if argNum < 0 || argNum > 10 {
			return
		}
		r := bytes.NewBuffer(data)
		_, _ = GetArgs(r, argNum)
	})
}
