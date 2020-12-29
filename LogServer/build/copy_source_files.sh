#!/bin/bash

SRV_HOME=`dirname $(realpath "$0")`/..

# create a temp directory

mkdir -p $SRV_HOME/build/src

# copy files to build

cp -r $SRV_HOME/core $SRV_HOME/build/src/
cp -r $SRV_HOME/protobuf $SRV_HOME/build/src/
cp    $SRV_HOME/go.mod $SRV_HOME/build/src/
cp    $SRV_HOME/main.go $SRV_HOME/build/src/
