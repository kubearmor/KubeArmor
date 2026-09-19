# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

# Build the manager binary
FROM golang:1.26@sha256:ef46d02b02ed68aa94b6a49ba5d3ec62003b8d5ce4b7497fe83e056f2e8fd378 AS builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download && go mod verify

# Copy the go source
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/ internal/
COPY handlers/ handlers/
COPY informer/ informer/
COPY types/ types/
COPY common/ common/

# Build
RUN CGO_ENABLED=0 GO111MODULE=on GOPROXY=off go build -a -o manager cmd/main.go

# Build controller with scratch as base image
FROM scratch AS controller
WORKDIR /
COPY --from=builder /workspace/manager .
ENTRYPOINT ["/manager"]

# Build controller with ubi as base image
FROM redhat/ubi10-minimal@sha256:04febb4a74cc9ef3eca05ef851d92957276cc6e82fe8cb1ee44abf5114d440d8 AS controller-ubi

ARG VERSION=latest

LABEL name="kubearmor-controller" \
      vendor="KubeArmor" \
      maintainer="Achref Ben Saad, Aryan Sharma, Aryan Bakliwal" \
      version=${VERSION} \
      release=${VERSION} \
      summary="kubearmor-controller container image based on redhat ubi" \
      description="kubearmor-controller container image based on redhat ubi"

RUN microdnf -y update && \
    microdnf -y install --nodocs --setopt=install_weak_deps=0 --setopt=keepcache=0 shadow-utils && \
    microdnf clean all

RUN groupadd --gid 1000 default \
  && useradd --uid 1000 --gid default --shell /bin/bash --create-home default
      
WORKDIR /
COPY --from=builder --chown=default:default /workspace/manager .
COPY LICENSE /licenses/license.txt

USER 1000
ENTRYPOINT ["/manager"]
