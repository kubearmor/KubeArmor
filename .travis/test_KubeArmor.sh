#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..

# move to KubeArmor
cd $ARMOR_HOME/KubeArmor

# test KubeArmor
make test

# move to LogServer
cd $ARMOR_HOME/LogServer

# test LogServer
make test
