CURDIR=$(shell pwd)

.PHONY: build
build:
	cd $(CURDIR); go build -o kubearmor-relay-server main.go

.PHONY: run
run: $(CURDIR)/kubearmor-relay-server
	cd $(CURDIR); ./kubearmor-relay-server

.PHONY: build-image
build-image:
	cd $(CURDIR); cp -r ../protobuf .
	cd $(CURDIR); docker build -t accuknox/kubearmor-relay-server:latest .
	cd $(CURDIR); rm -rf protobuf

.PHONY: push-image
push-image:
	cd $(CURDIR); docker push accuknox/kubearmor-relay-server:latest

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -f kubearmor-relay-server
	cd $(CURDIR); find . -name go.sum | xargs -I {} rm -f {}
