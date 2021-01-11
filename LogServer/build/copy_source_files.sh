#!/bin/bash

SERVER_HOME=`dirname $(realpath "$0")`/..

# copy LogServer
mkdir -p $SERVER_HOME/build/LogServer
cp -r $SERVER_HOME/server $SERVER_HOME/build/LogServer/
cp $SERVER_HOME/go.mod $SERVER_HOME/build/LogServer/
cp $SERVER_HOME/main.go $SERVER_HOME/build/LogServer/

# copy KubeArmor
cp -r $SERVER_HOME/../KubeArmor $SERVER_HOME/build/

# copy protobuf
cp -r $SERVER_HOME/../protobuf $SERVER_HOME/build/
