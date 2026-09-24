# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

CURDIR  := $(shell pwd)
RELAY_SERVER_IMG ?= kubearmor/kubearmor-relay-server
VERSION := latest

.PHONY: build
build:
	cd $(CURDIR); go mod tidy
	cd $(CURDIR); go build -o kubearmor-relay-server main.go

.PHONY: run
run: $(CURDIR)/kubearmor-relay-server
	cd $(CURDIR); ./kubearmor-relay-server

.PHONY: build-image
build-image:
	docker images | grep kubearmor-relay-server | awk '{print $$3}' | xargs -I {} docker rmi {}
	cd $(CURDIR); docker build -t ${RELAY_SERVER_IMG}:$(VERSION) -f ./Dockerfile ../../

.PHONY: push-image
push-image:
	cd $(CURDIR); docker push ${RELAY_SERVER_IMG}:$(VERSION)

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -f kubearmor-relay-server

.PHONY: gofmt
gofmt:
	cd $(CURDIR); gofmt -s -d $(shell find . -type f -name '*.go' -print)

.PHONY: golint
golint:
ifeq (, $(shell which golint))
	@{ \
	set -e ;\
	GOLINT_TMP_DIR=$$(mktemp -d) ;\
	cd $$GOLINT_TMP_DIR ;\
	go mod init tmp ;\
	go get -u golang.org/x/lint/golint ;\
	rm -rf $$GOLINT_TMP_DIR ;\
	}
endif
	cd $(CURDIR); golint ./...

.PHONY: gosec
gosec:
ifeq (, $(shell which gosec))
	@{ \
	go install github.com/securego/gosec/v2/cmd/gosec@latest;\
	}
endif
	cd $(CURDIR); gosec -exclude=G402,G304 ./...
