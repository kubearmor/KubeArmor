#!/bin/bash

# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# push accuknox/kubearmor-logserver

echo "[INFO] Pushing accuknox/kubearmor-logserver:$VERSION"
docker push accuknox/kubearmor-logserver:$VERSION

if [ $? == 0 ]; then
    echo "[PASSED] Pushed accuknox/kubearmor-logserver:$VERSION"
    exit 0
else
    echo "[FAILED] Failed to push accuknox/kubearmor-logserver:$VERSION"
    exit 1
fi
