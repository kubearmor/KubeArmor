#!/bin/bash

CURR=`dirname $(realpath "$0")`
cd $CURR

# generate protobuf
protoc --proto_path=. --go_out=plugins=grpc:. kubearmor.proto

# copy the protobuf to the feeder
cp kubearmor.pb.go ../KubeArmor/feeder/protobuf

# copy the protobuf to the logserver
cp kubearmor.pb.go ../LogServer/protobuf
