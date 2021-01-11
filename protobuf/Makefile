CURDIR=$(shell pwd)

.PHONY: build
build:
	@cd $(CURDIR); go get .
	cd $(CURDIR); protoc --proto_path=. --go_out=plugins=grpc:. kubearmor.proto

.PHONY: test
test:
	cd $(CURDIR); go test -v .

.PHONY: clean
clean:
	find . -name go.sum | xargs -I {} rm -f {}
