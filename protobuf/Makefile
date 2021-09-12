# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

CURDIR=$(shell pwd)

.PHONY: build
build:
	cd $(CURDIR); go get .
	cd $(CURDIR); protoc --proto_path=. --go_opt=paths=source_relative --go_out=plugins=grpc:. kubearmor.proto

.PHONY: clean
clean:
	cd $(CURDIR); find . -name go.sum | xargs -I {} rm -f {}
