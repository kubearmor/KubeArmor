#!/bin/bash

AUDIT_HOME=`dirname $(realpath "$0")`
cd $AUDIT_HOME

# remove old images

docker images | grep kubearmor-cos-auditd | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

echo "[INFO] Removed existing KubeArmor-COS-Auditd images"

# build a new image

if [ -z $1 ]; then
    echo "[INFO] Building accuknox/kubearmor-cos-auditd:latest"
    docker build -t accuknox/kubearmor-cos-auditd:latest  .
else
    echo "[INFO] Building build -t accuknox/kubearmor-cos-auditd:$1"
    docker build -t accuknox/kubearmor-cos-auditd:$1  .
fi

if [ $? == 0 ]; then
    echo "[PASSED] Built the KubeArmor-COS-Auditd image"
    exit 0
else
    echo "[FAILED] Failed to build the KubeArmor-COS-Auditd image"
    exit 1
fi
