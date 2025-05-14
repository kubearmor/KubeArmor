# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

CURDIR    := $(shell pwd)
DEPLOYDIR := $(realpath $(CURDIR)/../../deployments)
CHARTDIR  := $(realpath $(DEPLOYDIR)/helm/KubeArmorOperator)
CRDDIR    := $(realpath $(CHARTDIR)/crds)

# Image URL to use all building/pushing image targets
OPERATOR_IMG ?= kubearmor/kubearmor-operator
SNITCH_IMG ?= kubearmor/kubearmor-snitch
# Image Tag to use all building/pushing image targets
TAG ?= v0.1
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=true,preserveUnknownFields=false"
# Target platforms for build
PLATFORM ?= "linux/amd64,linux/arm64/v8"

BUNDLE_PKG ?= kubearmor-operator
BUNDLE_VER ?= latest

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

# Define a function to download a go tool if it is not installed.
define go-get-tool
@[ -f $(1) ] || { \
set -e; \
echo "Downloading $(2)" ;\
go install $(2) ;\
}
endef

.PHONY: all
all: get snitch kubearmor-operator

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

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: get
get: tidy
	go get ./...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: kubearmor-operator
kubearmor-operator: get
	go build -o kubearmor-operator cmd/operator/main.go

.PHONY: snitch
snitch: get
	go build -o snitch cmd/snitch-cmd/main.go

.PHONY: build
build: snitch kubearmor-operator

.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	docker build -t ${OPERATOR_IMG}:${TAG} -t ${OPERATOR_IMG}:latest --build-arg VERSION=${TAG} --target operator -f ./Dockerfile ../../
	docker build -t ${SNITCH_IMG}:${TAG} -t ${SNITCH_IMG}:latest --build-arg VERSION=${TAG} --target snitch -f ./Dockerfile ../../

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push ${OPERATOR_IMG}:${TAG}
	docker push ${SNITCH_IMG}:${TAG}

docker-buildx:
	docker buildx build --platform ${PLATFORM} --build-arg VERSION=${TAG} --push --target operator -t ${OPERATOR_IMG}:${TAG} -f ./Dockerfile ../../
	docker buildx build --platform ${PLATFORM} --build-arg VERSION=${TAG} --push --target snitch -t ${SNITCH_IMG}:${TAG} -f ./Dockerfile ../../

KUSTOMIZE_VERSION ?= v5.2.1
KUSTOMIZE = $(GOBIN)/kustomize
.PHONY: kustomize
kustomize: ## Download kustomize locally if necessary.
	GOBIN=$(GOBIN) go install sigs.k8s.io/kustomize/kustomize/v5@$(KUSTOMIZE_VERSION)

OPERATOR_SDK = ./bin/operator-sdk
.PHONY: operator-sdk
operator-sdk:
	@echo "Installing Operator SDK..."
	curl -LO https://github.com/operator-framework/operator-sdk/releases/latest/download/operator-sdk_linux_amd64
	chmod +x operator-sdk_linux_amd64
	sudo mv operator-sdk_linux_amd64 ./bin/operator-sdk

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: kustomize ## Deploy Operator Deployment, ClusterRole and ServiceAccount objects.
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: manifests
manifests: controller-gen kustomize## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	go mod tidy; $(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

	rm -r $(CRDDIR)/* && cp config/crd/bases/* $(CRDDIR)/
	$(KUSTOMIZE) build config/default | tee $(DEPLOYDIR)/operator/operator.yaml

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	go mod tidy; $(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

CONTROLLER_GEN = $(GOBIN)/controller-gen
.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.16.5)

client/gen:
	@echo "--> Running code-generator to generate clients"
	# prepare tool code-generator
	@mkdir -p ./tmp/code-generator
	@git clone https://github.com/kubernetes/code-generator.git --branch v0.22.1 --single-branch  ./tmp/code-generator
	# generate client
	GOPATH= GOROOT= ./tmp/code-generator/generate-groups.sh "all" github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/api operator.kubearmor.com:v1 --go-header-file hack/boilerplate.go.txt
	# check generated client at ./pkg/client
	@cp -r ./github.com/kubearmor/KubeArmor/pkg/KubeArmorOperator/client/* ./client/
	@rm -rf ./github.com ./tmp/code-generator

.PHONY: bundle
bundle: operator-sdk
	${OPERATOR_SDK} generate bundle --version ${BUNDLE_VER} --input-dir ./config --output-dir ./bundle --package ${BUNDLE_PKG}

.PHONY: clean
clean:
	rm snitch kubearmor-operator
