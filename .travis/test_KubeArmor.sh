#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`

# move to KubeArmor
cd $ARMOR_HOME/KubeArmor

# compile KubeArmor
make

# test KubeArmor
make test

# move to LogServer
cd $ARMOR_HOME/LogServer

# compile LogServer
make

# test LogServer
make test
