CURDIR=$(shell pwd)

.PHONY: build
build:
	go build -o kubearmor-logserver main.go

.PHONY: clean
clean:
	rm -f kubearmor-logserver go.sum

.PHONY: image
image:
	cd $(CURDIR)/build; $(MAKE)
