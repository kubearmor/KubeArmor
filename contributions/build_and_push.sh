#!/bin/bash

KBA_HOME=`dirname $(realpath "$0")`/..

if [ -z $1 ]; then
    echo "$0 [VERSION]"
    exit
fi

# KubeArmor

cd $KBA_HOME/KubeArmor/build

./build_kubearmor.sh $1
./push_kubearmor.sh $1

# KubeArmor-LogServer

cd $KBA_HOME/LogServer/build

./build_logserver.sh $1
./push_logserver.sh $1

# KubeArmor-COS-Auditd for GKE

cd $KBA_HOME/GKE/cos-auditd/build

./build_auditd.sh $1
./push_auditd.sh $1
