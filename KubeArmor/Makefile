CURDIR=$(shell pwd)

.PHONY: build
build:
	go build -o kubearmor main.go

.PHONY: clean
clean:
	rm -f kubearmor go.sum

.PHONY: image
image:
	cd $(CURDIR)/build; $(MAKE)
