#!/bin/bash

SERVER_PATH=`dirname $(realpath "$0")`/..

# create a temp directory

mkdir -p $SERVER_PATH/build/src

# copy files to build

cp -r $SERVER_PATH/server $SERVER_PATH/build/src/
cp $SERVER_PATH/go.mod $SERVER_PATH/build/src/
cp $SERVER_PATH/main.go $SERVER_PATH/build/src/
cp $SERVER_PATH/main_test.go $SERVER_PATH/build/src/
