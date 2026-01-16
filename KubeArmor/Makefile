# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

CURDIR          := $(shell pwd)
CRDDIR          := $(realpath $(CURDIR)/../deployments/CRD)
CONTRIBDIR      := $(realpath $(CURDIR)/../contribution)
GO_EXEC         := $(shell which go)
LOGNAME         := $(shell logname)
NETNEXT         := 0
DLV_EXEC         = $(GOPATH)/bin/dlv
DLV_LPORT       := 2345
DLV_RPORT       := $(shell expr $(DLV_LPORT) + $(NETNEXT))
KUBEARMOR_PID    = $(shell pgrep kubearmor)

ifeq (, $(shell which govvv))
$(shell go install github.com/ahmetb/govvv)	# This works for older go version
$(shell go install github.com/ahmetb/govvv@latest) # This works for new go version
endif

PKG      := $(shell go list ./buildinfo)
GIT_INFO := $(shell govvv -flags -pkg $(PKG))

.PHONY: build
build: protobuf
	cd $(CURDIR); go mod tidy
ifneq (, $(shell which bpftool))
ifneq (, $(wildcard /sys/kernel/btf/vmlinux))
	cd $(CURDIR); bpftool btf dump file /sys/kernel/btf/vmlinux format c > BPF/vmlinux.h || true
endif
ifneq (, $(shell which llvm-strip))
	if grep -q bpf '/sys/kernel/security/lsm'; then \
		cd $(CURDIR); go generate ./... || true; \
	fi
endif
endif
	cd $(CURDIR); CGO_ENABLED=0 go build -ldflags "$(GIT_INFO)" -o kubearmor main.go

.PHONY: protobuf
protobuf:
	cd $(CURDIR); make -C ../protobuf

.PHONY: build-test
build-test: testall
	cd $(CURDIR); go mod tidy
	cd $(CURDIR); sudo -E $(GO_EXEC) test -covermode=atomic -coverpkg=./... -c . -o kubearmor

.PHONY: run
run: build
	cd $(CRDDIR); kubectl apply -f KubeArmorPolicy.yaml
	cd $(CRDDIR); kubectl apply -f KubeArmorClusterPolicy.yaml
	cd $(CRDDIR); kubectl apply -f KubeArmorHostPolicy.yaml
	cd $(CURDIR); sudo rm -f /tmp/kubearmor.log
	cd $(CURDIR)/BPF; make clean
	cd $(CURDIR)/BPF; make
	cd $(CURDIR); DEBUG=true sudo -E ./kubearmor -logPath=/tmp/kubearmor.log -enableKubeArmorPolicy -enableKubeArmorHostPolicy -hostVisibility=process,file,network,capabilities -defaultFilePosture block -defaultCapabilitiesPosture block -defaultNetworkPosture block -hostDefaultFilePosture block -hostDefaultCapabilitiesPosture block -hostDefaultNetworkPosture block -annotateResources=true

.PHONY: run-container
run-container: build
	cd $(CURDIR); sudo rm -f /tmp/kubearmor.log
	cd $(CURDIR); sudo -E ./kubearmor -logPath=/tmp/kubearmor.log -enableKubeArmorHostPolicy -enableKubeArmorPolicy -k8s=false -criSocket=unix:///var/run/docker.sock

.PHONY: run-host-only
run-host-only: build
	cd $(CRDDIR); kubectl apply -f KubeArmorHostPolicy.yaml
	cd $(CURDIR); sudo rm -f /tmp/kubearmor.log
	cd $(CURDIR); sudo -E ./kubearmor -logPath=/tmp/kubearmor.log -enableKubeArmorPolicy=false -enableKubeArmorHostPolicy=true -hostVisibility=process,file,network,capabilities

.PHONY: test
test:
	cd $(CURDIR); sudo rm -f /tmp/kubearmor.log
	cd $(CURDIR)/feeder; go mod tidy
	cd $(CURDIR)/feeder; sudo -E $(GO_EXEC) clean -testcache .; sudo -E $(GO_EXEC) test -v .

.PHONY: testall
testall:
	cd $(CURDIR); sudo rm -f /tmp/kubearmor.log
	cd $(CURDIR)/feeder; go mod tidy
	cd $(CURDIR)/feeder; sudo -E $(GO_EXEC) clean -testcache .; sudo -E $(GO_EXEC) test -v -coverprofile=.coverprofile .
	cd $(CURDIR)/enforcer; go mod tidy
	cd $(CURDIR)/enforcer; sudo -E $(GO_EXEC) clean -testcache .; sudo -E $(GO_EXEC) test -v -coverprofile=.coverprofile .
	cd $(CURDIR)/BPF; make
	cd $(CURDIR)/monitor; go mod tidy
	cd $(CURDIR)/monitor; sudo -E $(GO_EXEC) clean -testcache .; sudo -E $(GO_EXEC) test -v -coverprofile=.coverprofile .

.PHONY: gofmt
gofmt:
	cd $(CURDIR); gofmt -s -w -d $(shell find . -type f -name '*.go' -print)

.PHONY: golint
golint:
ifeq (, $(shell which golint))
	@{ \
	set -e ;\
	GOLINT_TMP_DIR=$$(mktemp -d) ;\
	cd $$GOLINT_TMP_DIR ;\
	go mod init tmp ;\
	go get golang.org/x/lint/golint ;\
	go install golang.org/x/lint/golint ;\
	rm -rf $$GOLINT_TMP_DIR ;\
	}
endif
	cd $(CURDIR); golint ./...

.PHONY: gosec
gosec:
ifeq (, $(shell which gosec))
	@{ \
	set -e ;\
	GOSEC_TMP_DIR=$$(mktemp -d) ;\
	cd $$GOSEC_TMP_DIR ;\
	go mod init tmp ;\
	go get github.com/securego/gosec/v2/cmd/gosec ;\
	go install github.com/securego/gosec/v2/cmd/gosec ;\
	rm -rf $$GOSEC_TMP_DIR ;\
	}
endif
	cd $(CURDIR); gosec -exclude=G402,G115 ./...

.PHONY: local-release
local-release: build
ifeq (, $(shell which goreleaser))
	@{ \
	set -e ;\
	go install github.com/goreleaser/goreleaser@latest ;\
	}
endif
	cd $(CURDIR)/BPF; make clean
	cd $(CURDIR)/BPF; make
	cd $(CURDIR);ARCH=$(shell go env GOARCH) VERSION=$(shell git describe --tags --always --dirty) goreleaser release --clean --skip=publish,sign,validate --snapshot

.PHONY: scan
scan: 
	go install golang.org/x/vuln/cmd/govulncheck@latest ;\
	cd $(CURDIR);\
	govulncheck ./... ;\
	cd $(CURDIR)/../tests;\
	govulncheck ./... ;\
	cd $(CURDIR)/../protobuf;\
	govulncheck ./... ;\
	cd $(CURDIR)/../deployments;\
	govulncheck ./... ;\
	cd $(CURDIR)/../pkg/KubeArmorController ;\
	govulncheck ./... ;\
	cd $(CURDIR)/../pkg/KubeArmorOperator;\
	govulncheck ./... ;\

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -rf kubearmor karmor dist /tmp/kubearmor.log
	cd $(CURDIR); find . -name .coverprofile | xargs -I {} rm {}

.PHONY: vagrant-check
vagrant-check:
ifeq ($(LOGNAME), vagrant)
	$(error rule must be called from outside the vagrant environment)
endif

.PHONY: vagrant-up
vagrant-up: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) DLV_RPORT=$(DLV_RPORT) vagrant up; true

.PHONY: vagrant-status
vagrant-status: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) DLV_RPORT=$(DLV_RPORT) vagrant status; true

.PHONY: vagrant-reload
vagrant-reload: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) DLV_RPORT=$(DLV_RPORT) vagrant reload; true

.PHONY: vagrant-ssh
vagrant-ssh: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) DLV_RPORT=$(DLV_RPORT) vagrant ssh; true

.PHONY: vagrant-halt
vagrant-halt: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) DLV_RPORT=$(DLV_RPORT) vagrant halt; true

.PHONY: vagrant-destroy
vagrant-destroy: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) DLV_RPORT=$(DLV_RPORT) vagrant destroy; true

$(DLV_EXEC):
	go get -u github.com/go-delve/delve/cmd/dlv

.PHONY: debug-attach
debug-attach: $(DLV_EXEC)
ifeq ($(KUBEARMOR_PID), )
	$(error kubearmor must be running - execute 'make run' first)
endif
	sudo $(DLV_EXEC) attach $(KUBEARMOR_PID) --headless -l=:$(DLV_LPORT) --log --api-version 2 $(CURDIR)

