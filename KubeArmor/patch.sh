#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

# download gobpf
go get github.com/iovisor/gobpf

# check sudo
if [ -f /usr/bin/sudo ]; then
	SUDO=ON
fi

# fix module.go
for GOBPF in $(ls $GOPATH/pkg/mod/github.com/iovisor);
do
	if [ "$SUDO" == "ON" ]; then
		sudo sed -i 's/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid))/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid), 0)/g' $GOPATH/pkg/mod/github.com/iovisor/$GOBPF/bcc/module.go
	else
		sed -i 's/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid))/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid), 0)/g' $GOPATH/pkg/mod/github.com/iovisor/$GOBPF/bcc/module.go
	fi
done
