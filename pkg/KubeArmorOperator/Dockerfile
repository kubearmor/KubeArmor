# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

FROM docker.io/golang:1.20 as builder
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
COPY $OPERATOR_DIR/internal/controller internal/controller
COPY $OPERATOR_DIR/enforcer enforcer
COPY $OPERATOR_DIR/k8s k8s
COPY $OPERATOR_DIR/runtime runtime

# Build
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o operator cmd/main.go

FROM scratch
ARG OPERATOR_DIR=pkg/KubeArmorOperator
COPY --from=builder /KubeArmor/$OPERATOR_DIR/operator /operator
ENTRYPOINT ["/operator"]
