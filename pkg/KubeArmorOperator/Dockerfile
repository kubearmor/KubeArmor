# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

FROM docker.io/golang:1.22 as builder
ARG GOARCH
ARG GOOS

WORKDIR /KubeArmor

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# Copy the go source

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

COPY api api
# COPY client client
COPY cmd cmd
COPY common/ common/
COPY internal/controller/ internal/controller/
COPY internal/helm internal/helm
COPY internal/status internal/status
COPY embed/ embed/
COPY enforcer enforcer
COPY runtime runtime
COPY seccomp seccomp

# Build
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o operator cmd/operator/main.go
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o snitch cmd/snitch-cmd/main.go

FROM redhat/ubi9-minimal as operator

ARG VERSION=latest

LABEL name="kubearmor-operator" \
      vendor="Accuknox" \
      version=${VERSION} \
      release=${VERSION} \
      summary="kubearmor-operator container image based on redhat ubi" \
      description="kubearmor-operator to deploy and manage KubeArmor"

RUN microdnf -y update && \
    microdnf -y install --nodocs --setopt=install_weak_deps=0 --setopt=keepcache=0 shadow-utils libcap && \
    microdnf clean all

RUN groupadd --gid 1000 default \
  && useradd --uid 1000 --gid default --shell /bin/bash --create-home default          

COPY --from=builder --chown=1000:1000 /KubeArmor/operator /operator
COPY LICENSE /licenses/license.txt
  
USER 1000

ENTRYPOINT ["/operator"]

FROM redhat/ubi9-minimal as snitch

ARG VERSION=latest

LABEL name="kubearmor-snitch" \
      vendor="Accuknox" \
      version=${VERSION} \
      release=${VERSION} \
      summary="kubearmor-snitch container image based on redhat ubi" \
      description="KubeArmor-Snitch, A CLI Utility to Detect node related informations for KubeArmor"

COPY --from=builder /KubeArmor/snitch /snitch
COPY LICENSE /licenses/license.txt

ENTRYPOINT ["/snitch"]
