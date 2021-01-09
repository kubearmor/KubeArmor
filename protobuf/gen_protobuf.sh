#!/bin/bash

CURR=`dirname $(realpath "$0")`
cd $CURR

# generate protobuf
protoc --proto_path=. --go_out=plugins=grpc:. kubearmor.proto
