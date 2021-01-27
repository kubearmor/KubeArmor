#!/bin/bash

KBA_HOME=`dirname $(realpath "$0")`/..

if [ -z $1 ]; then
    echo "$0 [VERSION]"
    exit
fi

cd $KBA_HOME/KubeArmor/build

./build_kubearmor.sh $1
./push_kubearmor.sh $1
