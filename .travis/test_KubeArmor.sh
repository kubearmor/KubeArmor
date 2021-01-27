#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..

# move to KubeArmor
cd $ARMOR_HOME/KubeArmor

# test KubeArmor
make test
