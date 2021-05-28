### Builder

FROM golang:1.15.2-alpine3.12 as builder

RUN apk update
RUN apk add --no-cache bash git wget python3 linux-headers build-base clang clang-dev libc-dev bcc-dev librdkafka

WORKDIR /usr/src/KubeArmor

COPY ./protobuf ./protobuf

COPY ./LogClient ./LogClient
COPY ./MySQLClient ./MySQLClient
COPY ./KafkaClient ./KafkaClient

WORKDIR /usr/src/KubeArmor/kubearmor-relay-server

COPY ./core ./core
COPY ./go.mod ./go.mod
COPY ./main.go ./main.go

RUN GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o kubearmor-relay-server main.go

WORKDIR /usr/src/KubeArmor/LogClient

RUN GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o kubearmor-log-client main.go

WORKDIR /usr/src/KubeArmor/MySQLClient

RUN GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -o kubearmor-mysql-client main.go

WORKDIR /usr/src/KubeArmor/KafkaClient

RUN GOOS=linux GOARCH=amd64 go build -a -ldflags '-s -w' -tags musl -o kubearmor-kafka-client main.go

### Make executable image

FROM alpine:3.12

COPY --from=builder /usr/src/KubeArmor/kubearmor-relay-server/kubearmor-relay-server /KubeArmor/kubearmor-relay-server

COPY --from=builder /usr/src/KubeArmor/LogClient/kubearmor-log-client /kubearmor-log-client
COPY --from=builder /usr/src/KubeArmor/MySQLClient/kubearmor-mysql-client /kubearmor-mysql-client
COPY --from=builder /usr/src/KubeArmor/KafkaClient/kubearmor-kafka-client /kubearmor-kafka-client

ENTRYPOINT ["/KubeArmor/kubearmor-relay-server"]
