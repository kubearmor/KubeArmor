# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

FROM docker.io/golang:1.26@sha256:116489021a0d8ca3facf79f84ee69052cff88733547150a644d45c5eaa91dc43 AS builder
ARG GOARCH
ARG GOOS

WORKDIR /KubeArmor

# relative deps required by the operator
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
COPY $OPERATOR_DIR/hook hook
COPY $OPERATOR_DIR/utils utils


# Build
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o operator cmd/operator/main.go
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o snitch cmd/snitch-cmd/main.go
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o hook/hook ./hook

# Build operator image with scratch as base image
FROM scratch AS operator
ARG OPERATOR_DIR=pkg/KubeArmorOperator
COPY --from=builder /KubeArmor/$OPERATOR_DIR/operator /operator
ENTRYPOINT ["/operator"]

# Build operator image with ubi as base image
FROM redhat/ubi10-minimal AS operator-ubi

ARG VERSION=latest

LABEL name="kubearmor-operator" \
      vendor="KubeArmor" \
      maintainer="Achref Ben Saad, Aryan Sharma, Aryan Bakliwal" \
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

# Build snitch with scratch as base image
FROM scratch AS snitch
ARG OPERATOR_DIR=pkg/KubeArmorOperator
COPY --from=builder /KubeArmor/$OPERATOR_DIR/snitch /snitch
COPY --from=builder /KubeArmor/$OPERATOR_DIR/hook/hook /hook
ENTRYPOINT ["/snitch"]

# Build snitch with ubi as base image
FROM redhat/ubi10-minimal AS snitch-ubi

ARG VERSION=latest

LABEL name="kubearmor-snitch" \
      vendor="KubeArmor" \
      maintainer="Achref Ben Saad, Aryan Sharma, Aryan Bakliwal" \
      version=${VERSION} \
      release=${VERSION} \
      summary="kubearmor-snitch container image based on redhat ubi" \
      description="KubeArmor-Snitch, A CLI Utility to Detect node related information for KubeArmor"

ARG OPERATOR_DIR=pkg/KubeArmorOperator
COPY --from=builder /KubeArmor/$OPERATOR_DIR/snitch /snitch
COPY --from=builder /KubeArmor/$OPERATOR_DIR/hook/hook /hook
COPY LICENSE /licenses/license.txt

ENTRYPOINT ["/snitch"]
