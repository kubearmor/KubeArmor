#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`
cd $ARMOR_HOME

# compile KubeArmor if it doesn't exist
if [ ! -f "kubearmor" ]; then
    make
fi

# run KubeArmor
sudo -E ./kubearmor
