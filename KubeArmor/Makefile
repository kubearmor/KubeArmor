CURDIR=$(shell pwd)
GO_EXEC=$(shell which go)

.PHONY: build
build:
	$(CURDIR)/patch.sh
	cd $(CURDIR); go build -o kubearmor main.go

.PHONY: run
run: $(CURDIR)/kubearmor
	cd $(CURDIR); sudo rm -f /tmp/kubearmor.log
	cd $(CURDIR); sudo -E ./kubearmor -output=/tmp/kubearmor.log

.PHONY: test
test:
	cd $(CURDIR)/feeder; go clean -testcache .; go test -v .

.PHONY: testall
testall:
	cd $(CURDIR)/feeder; go clean -testcache .; go test -v .
	cd $(CURDIR)/enforcer; go clean -testcache .; sudo -E $(GO_EXEC) test -v .
	cd $(CURDIR)/monitor; go clean -testcache .; sudo -E $(GO_EXEC) test -v .

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -f kubearmor /tmp/kubearmor.log
	cd $(CURDIR); find . -name go.sum | xargs -I {} rm -f {}
	$(CURDIR)/build/clean_source_files.sh

.PHONY: image
image:
	cd $(CURDIR)/build; $(MAKE)
