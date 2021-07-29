CURDIR          := $(shell pwd)
CONTRIBDIR      := $(realpath $(CURDIR)/../contribution)
GO_EXEC         := $(shell which go)
LOGNAME         := $(shell logname)
NETNEXT         := 0
DLV_EXEC         = $(GOPATH)/bin/dlv
DLV_LPORT       := 2345
KUBEARMOR_PID    = $(shell pgrep kubearmor)

.PHONY: build
build:
	$(CURDIR)/patch.sh
	cd $(CURDIR); go mod tidy
	cd $(CURDIR); go build -o kubearmor main.go

.PHONY: build-test
build-test:
	$(CURDIR)/patch.sh
	cd $(CURDIR); go mod tidy
	cd $(CURDIR); sudo -E $(GO_EXEC) test -covermode=atomic -coverpkg=./... -c . -o kubearmor

.PHONY: run
run: $(CURDIR)/kubearmor
	cd $(CURDIR); sudo rm -f /tmp/kubearmor.log
	cd $(CURDIR); sudo -E ./kubearmor -logPath=/tmp/kubearmor.log

.PHONY: run-per-pod
run-per-pod: $(CURDIR)/kubearmor
	cd $(CURDIR); sudo rm -f /tmp/kubearmor.log
	cd $(CURDIR); sudo -E ./kubearmor -logPath=/tmp/kubearmor.log -enableEnforcerPerPod

.PHONY: run-with-host
run-with-host: $(CURDIR)/kubearmor
	cd $(CURDIR); sudo rm -f /tmp/kubearmor.log
	cd $(CURDIR); sudo -E ./kubearmor -logPath=/tmp/kubearmor.log -enableHostPolicy

.PHONY: test
test:
	cd $(CURDIR)/feeder; go mod tidy
	cd $(CURDIR)/feeder; go clean -testcache .; go test -v .

.PHONY: testall
testall:
	cd $(CURDIR)/feeder; go mod tidy
	cd $(CURDIR)/feeder; go clean -testcache .; go test -v -coverprofile=.coverprofile .
	cd $(CURDIR)/enforcer; go mod tidy
	cd $(CURDIR)/enforcer; go clean -testcache .; sudo -E $(GO_EXEC) test -v -coverprofile=.coverprofile .
	cd $(CURDIR)/monitor; go mod tidy
	cd $(CURDIR)/monitor; go clean -testcache .; sudo -E $(GO_EXEC) test -v -coverprofile=.coverprofile .

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -f kubearmor /tmp/kubearmor.log
	#cd $(CURDIR); find . -name go.sum | xargs -I {} rm -f {}
	$(CURDIR)/build/clean_source_files.sh

.PHONY: vagrant-check
vagrant-check:
ifeq ($(LOGNAME), vagrant)
	$(error rule must be called from outside the vagrant environment)
endif

.PHONY: vagrant-up
vagrant-up: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) vagrant up; true

.PHONY: vagrant-status
vagrant-status: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) vagrant status; true

.PHONY: vagrant-reload
vagrant-reload: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) vagrant reload; true

.PHONY: vagrant-ssh
vagrant-ssh: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) vagrant ssh; true

.PHONY: vagrant-halt
vagrant-halt: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) vagrant halt; true

.PHONY: vagrant-destroy
vagrant-destroy: vagrant-check
	cd $(CONTRIBDIR)/vagrant; NETNEXT=$(NETNEXT) vagrant destroy; true

$(DLV_EXEC):
	go get -u github.com/go-delve/delve/cmd/dlv

.PHONY: debug-attach
debug-attach: $(DLV_EXEC)
ifeq ($(KUBEARMOR_PID), )
	$(error kubearmor must be running - execute 'make run' first)
endif
	sudo $(DLV_EXEC) attach $(KUBEARMOR_PID) --headless -l=:$(DLV_LPORT) --log --api-version 2 $(CURDIR)
