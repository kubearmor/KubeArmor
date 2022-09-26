# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

FROM docker.io/golang:1.20 as builder
ARG GOARCH
ARG GOOS
WORKDIR /app
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# Copy the go source

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

COPY api api
COPY client client
COPY cmd cmd
COPY common common
COPY internal/controller internal/controller
COPY enforcer enforcer
COPY k8s k8s
COPY runtime runtime
# Build
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o operator cmd/main.go

FROM scratch
COPY --from=builder /app/operator /operator
ENTRYPOINT ["/operator"]
