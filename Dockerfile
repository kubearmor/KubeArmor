# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

### Builder

FROM golang:1.17.5-alpine3.15 as builder

RUN apk update
RUN apk add --no-cache bash git wget python3 linux-headers build-base clang clang-dev libc-dev bcc-dev protobuf

WORKDIR /usr/src/KubeArmor

COPY . .

WORKDIR /usr/src/KubeArmor/KubeArmor

RUN go install github.com/golang/protobuf/protoc-gen-go@latest
RUN make

### Make executable image

FROM alpine:3.15

RUN apk update
RUN echo "@community http://dl-cdn.alpinelinux.org/alpine/edge/community" | tee -a /etc/apk/repositories
RUN echo "@testing http://dl-cdn.alpinelinux.org/alpine/edge/testing" | tee -a /etc/apk/repositories

RUN apk update
RUN apk add bcc-tools
RUN apk add bash curl procps
RUN apk add apparmor@community apparmor-utils@community kubectl@testing

COPY --from=builder /usr/src/KubeArmor/KubeArmor/build/entrypoint.sh /KubeArmor/entrypoint.sh
COPY --from=builder /usr/src/KubeArmor/KubeArmor/kubearmor /KubeArmor/kubearmor
COPY --from=builder /usr/src/KubeArmor/KubeArmor/templates/* /KubeArmor/templates/
COPY --from=builder /usr/src/KubeArmor/KubeArmor/BPF/* /KubeArmor/BPF/
COPY --from=builder /usr/src/KubeArmor/GKE/*.sh /KubeArmor/GKE/

ENTRYPOINT ["/KubeArmor/entrypoint.sh"]
