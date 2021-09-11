#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# download gobpf
go get -u github.com/iovisor/gobpf

# fix module.go
for GOBPF in $(ls $GOPATH/pkg/mod/github.com/iovisor);
do
	echo $GOBPF
	sed -i 's/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid), 0)/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid))/g' $GOPATH/pkg/mod/github.com/iovisor/$GOBPF/bcc/module.go
done
