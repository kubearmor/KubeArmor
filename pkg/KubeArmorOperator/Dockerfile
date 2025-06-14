# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

FROM docker.io/golang:1.24 AS builder
ARG GOARCH
ARG GOOS

WORKDIR /KubeArmor

# relative deps requried by the operator
ADD deployments deployments
ADD KubeArmor KubeArmor
ADD pkg/KubeArmorController pkg/KubeArmorController

# KubeArmorOperator directory
ARG OPERATOR_DIR=pkg/KubeArmorOperator
WORKDIR /KubeArmor/$OPERATOR_DIR

# Copy the Go Modules manifests
COPY $OPERATOR_DIR/go.mod go.mod
COPY $OPERATOR_DIR/go.sum go.sum
# Copy the go source

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

COPY $OPERATOR_DIR/api api
COPY $OPERATOR_DIR/client client
COPY $OPERATOR_DIR/cmd cmd
COPY $OPERATOR_DIR/common common
COPY $OPERATOR_DIR/cert cert
COPY $OPERATOR_DIR/internal/controller internal/controller
COPY $OPERATOR_DIR/enforcer enforcer
COPY $OPERATOR_DIR/k8s k8s
COPY $OPERATOR_DIR/runtime runtime
COPY $OPERATOR_DIR/seccomp seccomp
COPY $OPERATOR_DIR/recommend recommend

# Build
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o operator cmd/operator/main.go
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o snitch cmd/snitch-cmd/main.go

FROM redhat/ubi9-minimal AS operator

ARG VERSION=latest

LABEL name="kubearmor-operator" \
      vendor="Accuknox" \
      maintainer="Barun Acharya, Ramakant Sharma" \
      version=${VERSION} \
      release=${VERSION} \
      summary="kubearmor-operator container image based on redhat ubi" \
      description="kubearmor-operator to deploy and manage KubeArmor"

RUN microdnf -y update && \
    microdnf -y install --nodocs --setopt=install_weak_deps=0 --setopt=keepcache=0 shadow-utils libcap && \
    microdnf clean all

RUN groupadd --gid 1000 default \
  && useradd --uid 1000 --gid default --shell /bin/bash --create-home default          

ARG OPERATOR_DIR=pkg/KubeArmorOperator
COPY --from=builder --chown=1000:1000 /KubeArmor/$OPERATOR_DIR/operator /operator
COPY LICENSE /licenses/license.txt
  
USER 1000

ENTRYPOINT ["/operator"]

FROM redhat/ubi9-minimal AS snitch

ARG VERSION=latest

LABEL name="kubearmor-snitch" \
      vendor="Accuknox" \
      maintainer="Barun Acharya, Ramakant Sharma" \
      version=${VERSION} \
      release=${VERSION} \
      summary="kubearmor-snitch container image based on redhat ubi" \
      description="KubeArmor-Snitch, A CLI Utility to Detect node related informations for KubeArmor"

ARG OPERATOR_DIR=pkg/KubeArmorOperator
COPY --from=builder /KubeArmor/$OPERATOR_DIR/snitch /snitch
COPY LICENSE /licenses/license.txt

ENTRYPOINT ["/snitch"]
