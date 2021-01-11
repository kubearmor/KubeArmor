#!/bin/bash

SERVER_HOME=`dirname $(realpath "$0")`/..

# create a temp directory

mkdir -p $SERVER_HOME/build/src

# copy files to build

cp -r $SERVER_HOME/server $SERVER_HOME/build/src/
cp $SERVER_HOME/go.mod $SERVER_HOME/build/src/
cp $SERVER_HOME/main.go $SERVER_HOME/build/src/
