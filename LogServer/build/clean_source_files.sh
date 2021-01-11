#!/bin/bash

SERVER_HOME=`dirname $(realpath "$0")`/..

rm -rf $SERVER_HOME/build/LogServer
rm -rf $SERVER_HOME/build/KubeArmor
rm -rf $SERVER_HOME/build/protobuf
