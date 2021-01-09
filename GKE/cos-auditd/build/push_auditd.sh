#!/bin/bash

# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# push accuknox/kubearmor-cos-auditd

echo "[INFO] Pushing accuknox/kubearmor-cos-auditd:$VERSION"
docker push accuknox/kubearmor-cos-auditd:$VERSION

if [ $? == 0 ]; then
    echo "[PASSED] Pushed accuknox/kubearmor-cos-auditd:$VERSION"
    exit 0
else
    echo "[FAILED] Failed to push accuknox/kubearmor-cos-auditd:$VERSION"
    exit 1
fi
