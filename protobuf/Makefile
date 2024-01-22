# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

CURDIR=$(shell pwd)

PROTOS:=kubearmor.proto kvm.proto policy.proto state.proto
PBGO:=$(PROTOS:.proto=.pb.go)

.PHONY: build
build: $(PBGO) go.sum

go.sum: go.mod
	go get .

%.pb.go: %.proto
	go mod tidy
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative,require_unimplemented_servers=false $<
	sed -i -e 's/\bPPID,omitempty\b/PPID,/' -e 's/\bUID,omitempty\b/UID,/' kubearmor.pb.go

.PHONY: clean
clean:
	rm -f go.sum *.pb.go
