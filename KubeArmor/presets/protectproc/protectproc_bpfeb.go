// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package protectproc

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"structs"

	"github.com/cilium/ebpf"
)

type protectprocArgBufsK struct {
	_    structs.HostLayout
	Okey struct {
		_     structs.HostLayout
		PidNs uint32
		MntNs uint32
	}
	Store protectprocBufsK
	Arg   [256]int8
}

type protectprocArgVal struct {
	_         structs.HostLayout
	ArgsArray [256]int8
}

type protectprocBufsK struct {
	_      structs.HostLayout
	Path   [256]int8
	Source [256]int8
}

type protectprocBufsT struct {
	_   structs.HostLayout
	Buf [32768]int8
}

type protectprocCmdArgsKey struct {
	_    structs.HostLayout
	Tgid uint64
	Ind  uint64
}

type protectprocPathname struct {
	_    structs.HostLayout
	Path [256]int8
}

// loadProtectproc returns the embedded CollectionSpec for protectproc.
func loadProtectproc() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ProtectprocBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load protectproc: %w", err)
	}

	return spec, err
}

// loadProtectprocObjects loads protectproc and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*protectprocObjects
//	*protectprocPrograms
//	*protectprocMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadProtectprocObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadProtectproc()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// protectprocSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type protectprocSpecs struct {
	protectprocProgramSpecs
	protectprocMapSpecs
	protectprocVariableSpecs
}

// protectprocProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type protectprocProgramSpecs struct {
	EnforceFile *ebpf.ProgramSpec `ebpf:"enforce_file"`
}

// protectprocMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type protectprocMapSpecs struct {
	ArgsBufk                    *ebpf.MapSpec `ebpf:"args_bufk"`
	Bufk                        *ebpf.MapSpec `ebpf:"bufk"`
	Bufs                        *ebpf.MapSpec `ebpf:"bufs"`
	BufsOff                     *ebpf.MapSpec `ebpf:"bufs_off"`
	CmdArgsBuf                  *ebpf.MapSpec `ebpf:"cmd_args_buf"`
	Events                      *ebpf.MapSpec `ebpf:"events"`
	KubearmorAlertThrottle      *ebpf.MapSpec `ebpf:"kubearmor_alert_throttle"`
	KubearmorArgsStore          *ebpf.MapSpec `ebpf:"kubearmor_args_store"`
	KubearmorArguments          *ebpf.MapSpec `ebpf:"kubearmor_arguments"`
	KubearmorConfig             *ebpf.MapSpec `ebpf:"kubearmor_config"`
	KubearmorContainers         *ebpf.MapSpec `ebpf:"kubearmor_containers"`
	KubearmorEvents             *ebpf.MapSpec `ebpf:"kubearmor_events"`
	KubearmorExecPids           *ebpf.MapSpec `ebpf:"kubearmor_exec_pids"`
	ProcFileAccess              *ebpf.MapSpec `ebpf:"proc_file_access"`
	ProtectprocPresetContainers *ebpf.MapSpec `ebpf:"protectproc_preset_containers"`
}

// protectprocVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type protectprocVariableSpecs struct {
	Unused *ebpf.VariableSpec `ebpf:"unused"`
}

// protectprocObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadProtectprocObjects or ebpf.CollectionSpec.LoadAndAssign.
type protectprocObjects struct {
	protectprocPrograms
	protectprocMaps
	protectprocVariables
}

func (o *protectprocObjects) Close() error {
	return _ProtectprocClose(
		&o.protectprocPrograms,
		&o.protectprocMaps,
	)
}

// protectprocMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadProtectprocObjects or ebpf.CollectionSpec.LoadAndAssign.
type protectprocMaps struct {
	ArgsBufk                    *ebpf.Map `ebpf:"args_bufk"`
	Bufk                        *ebpf.Map `ebpf:"bufk"`
	Bufs                        *ebpf.Map `ebpf:"bufs"`
	BufsOff                     *ebpf.Map `ebpf:"bufs_off"`
	CmdArgsBuf                  *ebpf.Map `ebpf:"cmd_args_buf"`
	Events                      *ebpf.Map `ebpf:"events"`
	KubearmorAlertThrottle      *ebpf.Map `ebpf:"kubearmor_alert_throttle"`
	KubearmorArgsStore          *ebpf.Map `ebpf:"kubearmor_args_store"`
	KubearmorArguments          *ebpf.Map `ebpf:"kubearmor_arguments"`
	KubearmorConfig             *ebpf.Map `ebpf:"kubearmor_config"`
	KubearmorContainers         *ebpf.Map `ebpf:"kubearmor_containers"`
	KubearmorEvents             *ebpf.Map `ebpf:"kubearmor_events"`
	KubearmorExecPids           *ebpf.Map `ebpf:"kubearmor_exec_pids"`
	ProcFileAccess              *ebpf.Map `ebpf:"proc_file_access"`
	ProtectprocPresetContainers *ebpf.Map `ebpf:"protectproc_preset_containers"`
}

func (m *protectprocMaps) Close() error {
	return _ProtectprocClose(
		m.ArgsBufk,
		m.Bufk,
		m.Bufs,
		m.BufsOff,
		m.CmdArgsBuf,
		m.Events,
		m.KubearmorAlertThrottle,
		m.KubearmorArgsStore,
		m.KubearmorArguments,
		m.KubearmorConfig,
		m.KubearmorContainers,
		m.KubearmorEvents,
		m.KubearmorExecPids,
		m.ProcFileAccess,
		m.ProtectprocPresetContainers,
	)
}

// protectprocVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadProtectprocObjects or ebpf.CollectionSpec.LoadAndAssign.
type protectprocVariables struct {
	Unused *ebpf.Variable `ebpf:"unused"`
}

// protectprocPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadProtectprocObjects or ebpf.CollectionSpec.LoadAndAssign.
type protectprocPrograms struct {
	EnforceFile *ebpf.Program `ebpf:"enforce_file"`
}

func (p *protectprocPrograms) Close() error {
	return _ProtectprocClose(
		p.EnforceFile,
	)
}

func _ProtectprocClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed protectproc_bpfeb.o
var _ProtectprocBytes []byte
