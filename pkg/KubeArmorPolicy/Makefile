# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

CURDIR := $(shell pwd)

# Image URL to use all building/pushing image targets
IMG ?= kubearmor/kubearmor-policy-manager
# Image Tag to use all building/pushing image targets
TAG ?= v0.1
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:crdVersions=v1"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: manager

# Run tests
test: generate fmt vet manifests
	go test ./... -coverprofile cover.out

# Build manager binary
manager: generate fmt vet
	go build -o bin/manager main.go

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./main.go

# Install CRDs into a cluster
install: manifests
	kustomize build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests
	kustomize build config/crd | kubectl delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	cd config/manager; kustomize edit set image controller=${IMG}:latest
	cd $(CURDIR); kustomize build config/default | sed 's/latest/${TAG}/g' | kubectl apply -f -

# Delete controller from the K8s cluster specified in ~/.kube/config.
delete: manifests
	kustomize build config/default | kubectl delete -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	cp config/crd/bases/security.kubearmor.com_kubearmorpolicies.yaml ../../deployments/CRD/KubeArmorPolicy.yaml
	cp config/crd/bases/security.kubearmor.com_kubearmorpolicies.yaml crd/KubeArmorPolicy.yaml

# Generate deployments
deployment: manifests
	cd config/manager; kustomize edit set image controller=${IMG}:latest
	cd $(CURDIR); kustomize build config/default > /tmp/kubearmor-policy-manager.yaml

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: controller-gen
	go mod tidy; $(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build:
	docker build -t ${IMG}:${TAG} -t ${IMG}:latest .

docker-buildx: ## Build docker image with the manager multiple archs.
	docker buildx build --platform ${PLATFORM} --push -t ${IMG}:${TAG} -t ${IMG}:latest .

# Push the docker image
docker-push:
	docker push ${IMG}:${TAG}
	docker push ${IMG}:latest

client/gen:
	@echo "--> Running code-generator to generate clients"
	# prepare tool code-generator
	@mkdir -p ./tmp/code-generator
	@git clone https://github.com/kubernetes/code-generator.git --branch v0.22.1 --single-branch  ./tmp/code-generator
	# generate client
	./tmp/code-generator/generate-groups.sh "all" github.com/kubearmor/KubeArmor/pkg/KubeArmorPolicy/client github.com/kubearmor/KubeArmor/pkg/KubeArmorPolicy/api security.kubearmor.com:v1 --go-header-file hack/boilerplate.go.txt
	# check generated client at ./pkg/client
	@cp -r ./github.com/kubearmor/KubeArmor/pkg/KubeArmorPolicy/client/* ./client/
	@rm -rf ./github.com ./tmp/code-generator

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.4.1 ;\
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.4.1 ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif

clean:
	rm -rf bin cover.out /tmp/kubearmor-policy-manager.yaml
