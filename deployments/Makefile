# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

CURDIR=$(shell pwd)

.PHONY: gen
gen: build
	$(CURDIR)/deploygen

.PHONY: build
build:
	cd $(CURDIR)
	go mod tidy
	go build -o deploygen

.PHONY: clean
clean:
	rm -f $(CURDIR)/deploygen

VERSION ?= stable
RELAY_VERSION ?= stable
KUBE_RBAC_PROXY ?= v0.15.0
KUBEARMOR_CHART_DIR = $(CURDIR)/helm/KubeArmor
KUBEARMOR_OPERATOR_CHART_DIR = $(CURDIR)/helm/KubeArmorOperator

.PHONY: pin-version
pin-version: yq
	$(YQ) eval ".kubearmorRelay.image.tag = \"$(RELAY_VERSION)\"" $(KUBEARMOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".kubearmorInit.image.tag = \"$(VERSION)\"" $(KUBEARMOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".kubearmorController.image.tag = \"$(VERSION)\"" $(KUBEARMOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".kubearmor.image.tag = \"$(VERSION)\"" $(KUBEARMOR_CHART_DIR)/values.yaml -
	$(YQ) eval ".snitch.image.tag = \"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".kubearmorOperator.image.tag = \"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i

REGISTRY ?= kubearmor
.PHONY: pin-images
pin-images: yq
	$(YQ) eval ".imagePinning = true" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".oci_meta.repo = \"$(REGISTRY)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".oci_meta.images.kubearmorRelay.tag = \"$(RELAY_VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".oci_meta.images.kubearmorInit.tag = \"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".oci_meta.images.kubearmorController.tag = \"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".oci_meta.images.kubearmor.tag = \"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".oci_meta.images.kubearmorSnitch.tag = \"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".oci_meta.images.kubearmorOperator.tag = \"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".oci_meta.images.kubeRbacProxy.tag = \"$(KUBE_RBAC_PROXY)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i

.PHONY: chart-version
chart-version: yq
	$(YQ) eval ".version = \"$(VERSION)\"" $(KUBEARMOR_CHART_DIR)/Chart.yaml -i
	$(YQ) eval ".appVersion = \"$(VERSION)\"" $(KUBEARMOR_CHART_DIR)/Chart.yaml -i
	$(YQ) eval ".version = \"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/Chart.yaml -i
	$(YQ) eval ".appVersion = \"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/Chart.yaml -i

.PHONY: embed-chart
embed-chart: yq
	$(YQ) eval ".helm.repository=\"embed\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".helm.chart=\"kubearmor\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i
	$(YQ) eval ".helm.version=\"$(VERSION)\"" $(KUBEARMOR_OPERATOR_CHART_DIR)/values.yaml -i

LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

YQ := $(LOCALBIN)/yq
yq:
ifeq (,$(wildcard $(YQ)))
ifeq (,$(shell ls $(YQ) 2>/dev/null))
	@{ \
	set -e ;\
	mkdir -p $(dir $(YQ)) ;\
	curl -L https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -o $(YQ); \
	chmod +x $(YQ); \
	}
endif
endif