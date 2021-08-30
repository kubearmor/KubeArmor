// +build amd64

package main

type hookType uint8

const (
	// list of entrypoint 
    sysCall        hookType = iota
    kprobe
    kretprobe
    tracepoint
    rawTracepoint
)

type Hook struct {
	// Location where the hook is to be attached
    progName       string
    attachName     string
    Type           hookType
}

type EventConfig struct {
	// Event handling, currently using ID and Name
    ID             int32
    Name           string
    Hooks          []Hook
}

var allEvents = map[int32]EventConfig{
	// Currently monitoring syscalls
    OpenEventID:         {ID: OpenEventID, Name: "open", Hooks: []Hook{{progName: "open", attachName: "__x64_sys_open", Type: kprobe}}},
    OpenatEventID:       {ID: OpenatEventID, Name: "openat", Hooks: []Hook{{progName: "openat", attachName: "__x64_sys_openat", Type: kprobe}}},
    ExecveEventID:       {ID: ExecveEventID, Name: "execve", Hooks: []Hook{{progName: "execve", attachName: "__x64_sys_execve", Type: kprobe}}},
    ExecveatEventID:     {ID: ExecveEventID, Name: "execveat", Hooks: []Hook{{progName: "execveat", attachName: "__x64_sys_execveat", Type: kprobe}}},
    SocketEventID:       {ID: SocketEventID, Name: "socket", Hooks: []Hook{{progName: "socket", attachName: "__x64_sys_socket", Type: kprobe}}},
    BindEventID:         {ID: BindEventID, Name: "bind", Hooks: []Hook{{progName: "bind", attachName: "__x64_sys_bind", Type: kprobe}}},
    ListenEventID:       {ID: ListenEventID, Name: "listen", Hooks: []Hook{{progName: "listen", attachName: "__x64_sys_listen", Type: kprobe}}},
    AcceptEventID:       {ID: AcceptEventID, Name: "accept", Hooks: []Hook{{progName: "accept", attachName: "__x64_sys_accept", Type: kprobe}}},
    ConnectEventID:      {ID: ConnectEventID, Name: "connect", Hooks: []Hook{{progName: "connect", attachName: "__x64_sys_connect", Type: kprobe}}},
}
