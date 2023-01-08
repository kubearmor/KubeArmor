FROM docker.io/golang:1.19 as builder
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

COPY main.go main.go
COPY cmd cmd
COPY common common
COPY controllers controllers
COPY enforcer enforcer
COPY k8s k8s
COPY runtime runtime
# Build
RUN CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -a -o kubearmor-operator main.go
RUN ln -s kubearmor-operator snitch

FROM debian
COPY --from=builder /app/kubearmor-operator /kubearmor-operator
COPY --from=builder /app/snitch /snitch
ENTRYPOINT ["/kubearmor-operator"]
