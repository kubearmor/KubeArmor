# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

# Build the manager binary
FROM golang:1.22 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/
COPY handlers/ handlers/

# Build
RUN CGO_ENABLED=0 GO111MODULE=on go build -a -o manager main.go

FROM redhat/ubi9-minimal as controller

ARG VERSION=latest

LABEL name="kubearmor-controller" \
      vendor="AccuKnox" \
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
