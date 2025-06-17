# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

### Builder

FROM golang:1.24-alpine3.21 AS builder

RUN apk --no-cache update
RUN apk add --no-cache git clang llvm make gcc protobuf protobuf-dev curl

WORKDIR /usr/src/KubeArmor

COPY . .

WORKDIR /usr/src/KubeArmor/KubeArmor

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

RUN make

WORKDIR /usr/src/KubeArmor/BPF

# install bpftool  
RUN arch=$(uname -m) bpftool_version=v7.3.0 && \
    if [[ "$arch" == "aarch64" ]]; then \
        arch=arm64; \
    elif [[ "$arch" == "x86_64" ]]; then \
        arch=amd64; \   
    fi && \
    curl -LO https://github.com/libbpf/bpftool/releases/download/$bpftool_version/bpftool-$bpftool_version-$arch.tar.gz && \
    tar -xzf bpftool-$bpftool_version-$arch.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/bpftool


COPY ./KubeArmor/BPF .

RUN make

### Builder test

FROM builder AS builder-test
WORKDIR /usr/src/KubeArmor/KubeArmor
RUN CGO_ENABLED=0 go test -covermode=atomic -coverpkg=./... -c . -o kubearmor-test

### Make executable image

FROM alpine:3.20 AS kubearmor

RUN echo "@community http://dl-cdn.alpinelinux.org/alpine/edge/community" | tee -a /etc/apk/repositories

RUN apk --no-cache update
RUN apk add apparmor@community apparmor-utils@community bash

COPY --from=builder /usr/src/KubeArmor/KubeArmor/kubearmor /KubeArmor/kubearmor
COPY --from=builder /usr/src/KubeArmor/BPF/*.o /opt/kubearmor/BPF/
COPY --from=builder /usr/src/KubeArmor/KubeArmor/templates/* /KubeArmor/templates/

ENTRYPOINT ["/KubeArmor/kubearmor"]

FROM kubearmor AS kubearmor-test
COPY --from=builder-test /usr/src/KubeArmor/KubeArmor/kubearmor-test /KubeArmor/kubearmor-test

ENTRYPOINT ["/KubeArmor/kubearmor-test"]

### TODO ###

### build apparmor_parser binary

## debian:10 uses glibc2.28 version similar to ubi9
# FROM debian:10 AS apparmor-builder
# RUN apt-get update && apt-get install -y apparmor
# RUN mkdir /tmp/apparmor && \
#     cp /sbin/apparmor_parser /tmp/apparmor/

### Make UBI-based executable image

FROM redhat/ubi9-minimal AS kubearmor-ubi

ARG VERSION=latest
ENV KUBEARMOR_UBI=true

LABEL name="kubearmor" \
      vendor="Accuknox" \
      maintainer="Barun Acharya, Ramakant Sharma" \
      version=${VERSION} \
      release=${VERSION} \
      summary="kubearmor container image based on redhat ubi" \
      description="KubeArmor is a cloud-native runtime security enforcement system that restricts the behavior \
                  (such as process execution, file access, and networking operations) of pods, containers, and nodes (VMs) \
                  at the system level."

RUN microdnf -y update && \
    microdnf -y install --nodocs --setopt=install_weak_deps=0 --setopt=keepcache=0 shadow-utils procps libcap && \
    microdnf clean all

RUN groupadd --gid 1000 default \
  && useradd --uid 1000 --gid default --shell /bin/bash --create-home default

COPY LICENSE /licenses/license.txt
COPY --from=builder --chown=default:default /usr/src/KubeArmor/KubeArmor/kubearmor /KubeArmor/kubearmor
COPY --from=builder --chown=default:default /usr/src/KubeArmor/BPF/*.o /opt/kubearmor/BPF/
COPY --from=builder --chown=default:default /usr/src/KubeArmor/KubeArmor/templates/* /KubeArmor/templates/

# TODO
# COPY --from=apparmor-builder /tmp/apparmor/apparmor_parser /usr/sbin/
# RUN chmod u+s /usr/sbin/apparmor_parser

RUN setcap "cap_sys_admin=ep cap_sys_ptrace=ep cap_ipc_lock=ep cap_sys_resource=ep cap_dac_override=ep cap_dac_read_search=ep" /KubeArmor/kubearmor

USER 1000
ENTRYPOINT ["/KubeArmor/kubearmor"]

### Make UBI-based test executable image for coverage calculation
FROM redhat/ubi9-minimal AS kubearmor-ubi-test

ARG VERSION=latest
ENV KUBEARMOR_UBI=true

LABEL name="kubearmor" \
      vendor="Accuknox" \
      maintainer="Barun Acharya, Ramakant Sharma" \
      version=${VERSION} \
      release=${VERSION} \
      summary="kubearmor container image based on redhat ubi" \
      description="KubeArmor is a cloud-native runtime security enforcement system that restricts the behavior \
                  (such as process execution, file access, and networking operations) of pods, containers, and nodes (VMs) \
                  at the system level."

RUN microdnf -y update && \
    microdnf -y install --nodocs --setopt=install_weak_deps=0 --setopt=keepcache=0 shadow-utils procps libcap && \
    microdnf clean all

RUN groupadd --gid 1000 default \
  && useradd --uid 1000 --gid default --shell /bin/bash --create-home default

COPY LICENSE /licenses/license.txt
COPY --from=builder --chown=default:default /usr/src/KubeArmor/KubeArmor/kubearmor /KubeArmor/kubearmor
COPY --from=builder --chown=default:default /usr/src/KubeArmor/BPF/*.o /opt/kubearmor/BPF/
COPY --from=builder --chown=default:default /usr/src/KubeArmor/KubeArmor/templates/* /KubeArmor/templates/
COPY --from=builder-test --chown=default:default /usr/src/KubeArmor/KubeArmor/kubearmor-test /KubeArmor/kubearmor-test

RUN setcap "cap_sys_admin=ep cap_sys_ptrace=ep cap_ipc_lock=ep cap_sys_resource=ep cap_dac_override=ep cap_dac_read_search=ep" /KubeArmor/kubearmor-test

USER 1000
ENTRYPOINT ["/KubeArmor/kubearmor-test"]
