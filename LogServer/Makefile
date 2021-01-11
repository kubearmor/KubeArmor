CURDIR=$(shell pwd)

.PHONY: build
build:
	@cd $(CURDIR)/server; go get .
	cd $(CURDIR); go build -o kubearmor-logserver main.go

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
