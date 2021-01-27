CURDIR=$(shell pwd)

.PHONY: build
build:
	cd $(CURDIR); go build -o kubearmor-client main.go

.PHONY: run
run: $(CURDIR)/kubearmor-client
	cd $(CURDIR); sudo rm -f /tmp/kubearmor-message /tmp/kubearmor-log
	cd $(CURDIR); ./kubearmor-client -msg=/tmp/kubearmor-message -log=/tmp/kubearmor-log

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -f kubearmor-client /tmp/kubearmor-message /tmp/kubearmor-log
	cd $(CURDIR); find . -name go.sum | xargs -I {} rm -f {}
