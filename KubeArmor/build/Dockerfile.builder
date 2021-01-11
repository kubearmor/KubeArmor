### Builder

FROM golang:1.15.2-alpine3.12

RUN apk update
RUN apk add --no-cache bash git wget python3 linux-headers build-base clang clang-dev libc-dev bcc-dev
