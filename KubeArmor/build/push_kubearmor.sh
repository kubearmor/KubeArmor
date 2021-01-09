#!/bin/bash

# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# push accuknox/kubearmor

echo "[INFO] Pushing accuknox/kubearmor:$VERSION"
docker push accuknox/kubearmor:$VERSION

if [ $? == 0 ]; then
    echo "[PASSED] Pushed accuknox/kubearmor:$VERSION"
    exit 0
else
    echo "[FAILED] Failed to push accuknox/kubearmor:$VERSION"
    exit 1
fi
