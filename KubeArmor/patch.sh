#!/bin/bash

# download gobpf
go get github.com/iovisor/gobpf

# fix module.go
for GOBPF in $(ls $GOPATH/pkg/mod/github.com/iovisor);
do
	if [ -f /usr/bin/sudo ]; then
		sudo sed -i 's/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid))/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid), 0)/g' $GOPATH/pkg/mod/github.com/iovisor/$GOBPF/bcc/module.go
	else
		sed -i 's/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid))/C.bpf_attach_uprobe(C.int(fd), attachType, evNameCS, binaryPathCS, (C.uint64_t)(addr), (C.pid_t)(pid), 0)/g' $GOPATH/pkg/mod/github.com/iovisor/$GOBPF/bcc/module.go
	fi
done
