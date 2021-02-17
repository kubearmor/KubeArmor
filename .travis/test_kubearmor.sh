#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/..

# test KubeArmor

$ARMOR_HOME/KubeArmor/build/test_kubearmor.sh

if [ $? != 0 ]; then
    exit 1
else
    exit 0
fi
