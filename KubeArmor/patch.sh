#!/bin/bash

# download gobpf
go get github.com/accuknox/gobpf

# fix module.go
for GOBPF in $(ls $GOPATH/pkg/mod/github.com/accuknox/gobpf);
do
	echo $GOBPF
done
