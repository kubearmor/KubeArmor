# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

### Builder

FROM golang:1.15.2-alpine3.12 as builder

RUN apk update
RUN apk add --no-cache bash git wget python3 linux-headers build-base clang clang-dev libc-dev bcc-dev

WORKDIR /usr/src/KubeArmor

COPY ./KubeArmor ./KubeArmor
COPY ./protobuf ./protobuf
COPY ./GKE ./GKE

WORKDIR /usr/src/KubeArmor/KubeArmor

RUN ./patch.sh
RUN GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o kubearmor main.go

### Make executable image

FROM alpine:3.14

RUN apk update
RUN echo "@community http://dl-cdn.alpinelinux.org/alpine/edge/community" | tee -a /etc/apk/repositories
RUN echo "@testing http://dl-cdn.alpinelinux.org/alpine/edge/testing" | tee -a /etc/apk/repositories

RUN apk update
RUN apk add bash curl procps bcc@community bcc-dev@community
RUN apk add apparmor@community apparmor-utils@community kubectl@testing

COPY --from=builder /usr/src/KubeArmor/KubeArmor/kubearmor /KubeArmor/kubearmor
COPY --from=builder /usr/src/KubeArmor/KubeArmor/BPF/* /KubeArmor/BPF/
COPY --from=builder /usr/src/KubeArmor/GKE/*.sh /KubeArmor/GKE/

ENTRYPOINT ["/KubeArmor/kubearmor"]
