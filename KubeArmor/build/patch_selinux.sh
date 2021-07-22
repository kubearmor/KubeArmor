#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


# download gobpf
go get -u github.com/iovisor/gobpf

# fix module.go
for GOBPF in $(ls $GOPATH/pkg/mod/github.com/iovisor);
do
	echo $GOBPF
	sed -i 's/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid), 0)/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid))/g' $GOPATH/pkg/mod/github.com/iovisor/$GOBPF/bcc/module.go
	sed -i "s/C.bpf_module_create_c_from_string(cs, 2, (\*\*C.char)(\&cflagsC\[0\]), C.int(len(cflagsC)), (C.bool)(true), nil)/C.bpf_module_create_c_from_string(cs, 2, (\*\*C.char)(\&cflagsC\[0\]), C.int(len(cflagsC)), (C.bool)(true))/g" $GOPATH/pkg/mod/github.com/iovisor/$GOBPF/bcc/module.go
	sed -i 's/C.bcc_func_load(bpf.p, C.int(uint32(progType)), nameCS, start, size, license, version, C.int(logLevel), logBufP, C.uint(len(logBuf)), nil)/C.bcc_func_load(bpf.p, C.int(uint32(progType)), nameCS, start, size, license, version, C.int(logLevel), logBufP, C.uint(len(logBuf)))/g' $GOPATH/pkg/mod/github.com/iovisor/$GOBPF/bcc/module.go
done
