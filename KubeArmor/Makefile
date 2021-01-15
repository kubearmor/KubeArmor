CURDIR=$(shell pwd)
GO_EXEC=$(shell which go)

.PHONY: build
build:
	$(CURDIR)/patch.sh
	@cd $(CURDIR)/audit; go get .
	@cd $(CURDIR)/common; go get .
	@cd $(CURDIR)/core; go get .
	@cd $(CURDIR)/discovery; go get .
	@cd $(CURDIR)/enforcer; go get .
	@cd $(CURDIR)/feeder; go get .
	@cd $(CURDIR)/log; go get .
	@cd $(CURDIR)/monitor; go get .
	@cd $(CURDIR)/types; go get .
	cd $(CURDIR); go build -o kubearmor main.go

.PHONY: run
run: $(CURDIR)/kubearmor
	@sudo rm -f /tmp/kubearmor-audit.log /tmp/kubearmor-system.log
	cd $(CURDIR); sudo -E ./kubearmor -audit=file:/tmp/kubearmor-audit.log -system=file:/tmp/kubearmor-system.log

.PHONY: run-with-logserver
run-with-logserver: $(CURDIR)/kubearmor
	cd $(CURDIR); sudo -E ./kubearmor -audit=grpc:localhost:32767 -system=grpc:localhost:32767

.PHONY: test
test:
	cd $(CURDIR)/audit; go clean -testcache .; go test -v .
	cd $(CURDIR)/feeder; go clean -testcache .; go test -v .

.PHONY: testall
testall:
	cd $(CURDIR)/audit; go clean -testcache .; go test -v .
	cd $(CURDIR)/enforcer; go clean -testcache .; sudo -E $(GO_EXEC) test -v .
	cd $(CURDIR)/feeder; go clean -testcache .; go test -v .
	cd $(CURDIR)/monitor; go clean -testcache .; sudo -E $(GO_EXEC) test -v .

.PHONY: clean
clean:
	rm -f kubearmor
	find . -name go.sum | xargs -I {} rm -f {}
	$(CURDIR)/build/clean_source_files.sh

.PHONY: image
image:
	cd $(CURDIR)/build; $(MAKE)
