# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

### build syscall checker

FROM golang:1.18-alpine3.15 as init-builder
WORKDIR /usr/src/KubeArmor
COPY ./KubeArmor/BPF/tests/main.go main.go
COPY ./KubeArmor/BPF/tests/go.mod go.mod
COPY ./KubeArmor/BPF/tests/go.sum go.sum

RUN go build -o syscheck main.go

### Make compiler image
FROM alpine:3.15 as kubearmor-init

RUN apk --no-cache update
RUN echo "@edge http://dl-cdn.alpinelinux.org/alpine/edge/main" | tee -a /etc/apk/repositories
RUN echo "@edge http://dl-cdn.alpinelinux.org/alpine/edge/community" | tee -a /etc/apk/repositories

RUN apk --no-cache update
RUN apk --no-cache add bash git clang llvm make gcc bpftool@edge

COPY ./KubeArmor/BPF /KubeArmor/BPF/
COPY ./KubeArmor/build/compile.sh /KubeArmor/compile.sh
COPY --from=init-builder /usr/src/KubeArmor/syscheck /KubeArmor/BPF/tests/syscheck
ENTRYPOINT ["/KubeArmor/compile.sh"]

### Builder

FROM golang:1.18-alpine3.15 as builder

RUN apk --no-cache update
RUN apk add --no-cache bash git wget python3 linux-headers build-base clang clang-dev libc-dev llvm make gcc protobuf

WORKDIR /usr/src/KubeArmor

COPY . .

WORKDIR /usr/src/KubeArmor/KubeArmor

RUN go install github.com/golang/protobuf/protoc-gen-go@latest
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

ENTRYPOINT ["/KubeArmor/kubearmor"]
