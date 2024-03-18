# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

CURDIR := $(shell pwd)

# Image URL to use all building/pushing image targets
IMG ?= kubearmor/kubearmor-controller
# Image Tag to use all building/pushing image targets
TAG ?= v0.1
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=true,preserveUnknownFields=false"
# Target platforms for build
PLATFORM ?= "linux/amd64,linux/arm64/v8"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	go mod tidy; $(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases
	cp config/crd/bases/security.kubearmor.com_kubearmorpolicies.yaml ../../deployments/CRD/KubeArmorPolicy.yaml
	cp config/crd/bases/security.kubearmor.com_kubearmorpolicies.yaml crd/KubeArmorPolicy.yaml
	cp config/crd/bases/security.kubearmor.com_kubearmorpolicies.yaml ../../deployments/helm/KubeArmor/templates/crds/ksp.yaml
	cp config/crd/bases/security.kubearmor.com_kubearmorhostpolicies.yaml ../../deployments/CRD/KubeArmorHostPolicy.yaml
	cp config/crd/bases/security.kubearmor.com_kubearmorhostpolicies.yaml crd/KubeArmorHostPolicy.yaml
	cp config/crd/bases/security.kubearmor.com_kubearmorhostpolicies.yaml ../../deployments/helm/KubeArmor/templates/crds/hsp.yaml

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	go mod tidy; $(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

ENVTEST_ASSETS_DIR=$(shell pwd)/testbin
.PHONY: test
test: manifests generate fmt vet ## Run tests.
	mkdir -p ${ENVTEST_ASSETS_DIR}
	test -f ${ENVTEST_ASSETS_DIR}/setup-envtest.sh || curl -sSLo ${ENVTEST_ASSETS_DIR}/setup-envtest.sh https://raw.githubusercontent.com/kubernetes-sigs/controller-runtime/v0.8.3/hack/setup-envtest.sh
	source ${ENVTEST_ASSETS_DIR}/setup-envtest.sh; fetch_envtest_tools $(ENVTEST_ASSETS_DIR); setup_envtest_env $(ENVTEST_ASSETS_DIR); go test ./... -coverprofile cover.out

##@ Build

.PHONY: build
build: generate fmt vet ## Build manager binary.
	go build -o bin/manager main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./main.go

.PHONY: docker-build
docker-build: build ## Build docker image with the manager.
	docker build -t ${IMG}:${TAG} -t ${IMG}:latest --build-arg VERSION=${TAG} .

docker-buildx: build ## Build docker image with the manager multiple archs.
	docker buildx build --platform ${PLATFORM} --build-arg VERSION=${TAG} --push -t ${IMG}:${TAG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push ${IMG}:${TAG}
	docker push ${IMG}:latest

client/gen:
	@echo "--> Running code-generator to generate clients"
	# prepare tool code-generator
	@mkdir -p ./tmp/code-generator
	@git clone https://github.com/kubernetes/code-generator.git --branch v0.22.1 --single-branch  ./tmp/code-generator
	# generate client
	GOPATH= GOROOT= ./tmp/code-generator/generate-groups.sh "all" github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api security.kubearmor.com:v1 --go-header-file hack/boilerplate.go.txt
	# check generated client at ./pkg/client
	@cp -r ./github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/* ./client/
	@rm -rf ./github.com ./tmp/code-generator

##@ Deployment

deploy-cert-manager: ensure-cmctl ## Deploy cert-manager before deploying the admission controller
	kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.8.0/cert-manager.yaml
	kubectl wait pods --for=condition=ready -n cert-manager -l app.kubernetes.io/instance=cert-manager
	@echo "Waiting for cert manager to inject CA bundle, this can take up to 5 minutes"
	$(CMCTL) check api  --wait 300s

CMCTL = /usr/local/bin/cmctl
ensure-cmctl:
	$(call get-cmctl,$(CMCTL))

define get-cmctl 
@[ -f $(1) ] || { \
OS=$$(go env GOOS) ;\
ARCH=$$(go env GOARCH) ;\
echo "Downloading cmctl" ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
curl -sSL -o cmctl.tar.gz https://github.com/cert-manager/cert-manager/releases/download/v1.7.2/cmctl-$$OS-$$ARCH.tar.gz ;\
echo "Installing ..." ;\
tar xzf cmctl.tar.gz ;\
sudo mv cmctl $(1) ;\
rm -rf $$TMP_DIR ;\
echo "cmctl is now under $(1)" ;\
}
endef

delete-cert-manager: ## Delete cert-manager when deleting the admission controller
	kubectl delete -f https://github.com/cert-manager/cert-manager/releases/download/v1.8.0/cert-manager.yaml

deploy: manifests kustomize deploy-cert-manager ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager; $(KUSTOMIZE) edit set image controller=${IMG}:latest
	cd $(CURDIR); $(KUSTOMIZE) build config/default | \
		sed 's/control-plane: controller-manager/kubearmor-app: kubearmor-controller/g' | \
		sed -e "1,7d" | kubectl apply -f -

delete-controller:  ## Delete controller from the K8s cluster specified in ~/.kube/config.
	cd $(CURDIR); $(KUSTOMIZE) build config/default | \
		sed 's/control-plane: controller-manager/kubearmor-app: kubearmor-controller/g' | \
		sed -e "1,7d" | kubectl delete -f -

delete: delete-controller delete-cert-manager ## Delete controller and cert manager from the K8s cluster specified in ~/.kube/config.


deployment: manifests kustomize
	cd config/manager; $(KUSTOMIZE) edit set image controller=${IMG}:latest
	cd $(CURDIR); $(KUSTOMIZE) build config/default | \
		sed 's/control-plane: controller-manager/kubearmor-app: kubearmor-controller/g' | \
		sed -e "1,7d" > ../../deployments/controller/kubearmor-controller.yaml

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install-crd
install-crd: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall-crd
uninstall-crd: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

CONTROLLER_GEN = $(GOBIN)/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.14.0)

KUSTOMIZE = /usr/local/bin/kustomize
.PHONY: kustomize
kustomize: ## Download kustomize locally if necessary.
	$(call go-get-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v3@v3.8.7)

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
go mod tidy ;\
go get $(2) ;\
GOBIN=$(HOME)/go/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

clean:
	rm -rf bin testbin go.sum cover.out /tmp/KubeArmorController.yaml
