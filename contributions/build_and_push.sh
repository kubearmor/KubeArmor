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

./build_kubearmor.sh latest
./push_kubearmor.sh latest

# KubeArmor-COS-Auditd for GKE

cd $KBA_HOME/GKE/cos-auditd/build

./build_auditd.sh $1
./push_auditd.sh $1

./build_auditd.sh latest
./push_auditd.sh latest

# KubeArmor-LogServer

cd $KBA_HOME/LogServer/build

./build_logserver.sh $1
./push_logserver.sh $1

./build_logserver.sh latest
./push_logserver.sh latest
