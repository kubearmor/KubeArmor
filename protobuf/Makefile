# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

CURDIR=$(shell pwd)

PROTOS:=kubearmor.proto kvm.proto policy.proto
PBGO:=$(PROTOS:.proto=.pb.go)

.PHONY: build
build: $(PBGO) go.sum

go.sum: go.mod
	go get .

%.pb.go: %.proto
	protoc --proto_path=. --go_opt=paths=source_relative --go_out=plugins=grpc:. $<

.PHONY: clean
clean:
	rm -f go.sum *.pb.go
