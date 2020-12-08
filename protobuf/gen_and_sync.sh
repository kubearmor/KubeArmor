#!/bin/bash

CURR=`dirname $(realpath "$0")`

cd $CURR
protoc --proto_path=. --go_out=plugins=grpc:. kubearmor.proto

cp kubearmor.pb.go ../KubeArmor/feeder/protobuf
cp kubearmor.pb.go ../LogServer/protobuf
