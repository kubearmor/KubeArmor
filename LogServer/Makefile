CURDIR=$(shell pwd)

.PHONY: build
build:
	@cd $(CURDIR)/server; go get .
	cd $(CURDIR); go build -o kubearmor-logserver main.go

.PHONY: run
run: $(CURDIR)/kubearmor-logserver
	@sudo rm -f /tmp/kubearmor-audit.log /tmp/kubearmor-system.log
	cd $(CURDIR); ./kubearmor-logserver -audit=file:/tmp/kubearmor-audit.log -system=file:/tmp/kubearmor-system.log

.PHONY: test
test:
	cd $(CURDIR)/server; go clean -testcache .; go test -v .

.PHONY: clean
clean:
	rm -f kubearmor-logserver
	find . -name go.sum | xargs -I {} rm -f {}
	$(CURDIR)/build/clean_source_files.sh

.PHONY: image
image:
	cd $(CURDIR)/build; $(MAKE)
