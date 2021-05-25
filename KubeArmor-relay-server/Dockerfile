### Builder

FROM golang:1.15.2-alpine3.12 as builder

RUN apk update
RUN apk add build-base

WORKDIR /usr/src

COPY ./protobuf ./protobuf

WORKDIR /usr/src/kubearmor-relay-server

COPY ./core ./core
COPY ./go.mod ./go.mod
COPY ./main.go ./main.go

RUN GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o kubearmor-relay-server main.go

### Make executable image

FROM alpine:3.12

COPY --from=builder /usr/src/kubearmor-relay-server/kubearmor-relay-server /kubearmor-relay-server

ENTRYPOINT ["/kubearmor-relay-server"]
