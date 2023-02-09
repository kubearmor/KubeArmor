# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

### Builder

FROM golang:1.18-alpine3.15 as builder

RUN apk --no-cache update
RUN apk add --no-cache bash git wget python3 linux-headers build-base clang clang-dev libc-dev llvm make gcc protobuf

WORKDIR /usr/src/KubeArmor

COPY . .

WORKDIR /usr/src/KubeArmor/KubeArmor

RUN go install github.com/golang/protobuf/protoc-gen-go@latest
RUN GRPC_HEALTH_PROBE_VERSION=v0.4.15 && \
    wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64
RUN make

### Make executable image

FROM alpine:3.15 as kubearmor

RUN apk --no-cache update
RUN echo "@community http://dl-cdn.alpinelinux.org/alpine/edge/community" | tee -a /etc/apk/repositories
RUN echo "@testing http://dl-cdn.alpinelinux.org/alpine/edge/testing" | tee -a /etc/apk/repositories

RUN apk --no-cache update
RUN apk add bash curl procps
RUN apk add apparmor@community apparmor-utils@community kubectl@testing

COPY --from=builder /usr/src/KubeArmor/KubeArmor/kubearmor /KubeArmor/kubearmor
COPY --from=builder /usr/src/KubeArmor/KubeArmor/templates/* /KubeArmor/templates/
COPY --from=builder /bin/grpc_health_probe ./grpc_health_probe


ENTRYPOINT ["/KubeArmor/kubearmor"]
