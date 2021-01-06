#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`
cd $ARMOR_HOME

if [ ! -f "kubearmor" ]; then
    make
fi

sudo -E ./kubearmor
