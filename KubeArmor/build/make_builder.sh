#!/bin/bash

# remove old images

docker images | grep kubearmor | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

# build a base image

echo "[INFO] Building accuknox/kubearmor:base"
docker build -t accuknox/kubearmor:base . -f Dockerfile.builder

if [ $? != 0 ]; then
    echo "[FAILED] Failed to build accuknox/kubearmor:base"
    exit 1
else
    echo "[PASSED] Built accuknox/kubearmor:base"
fi

# push accuknox/kubearmor:base

echo "[INFO] Pushing accuknox/kubearmor:base"
docker push accuknox/kubearmor:base

if [ $? != 0 ]; then
    echo "[FAILED] Failed to push accuknox/kubearmor:base"
    exit 1
else
    echo "[PASSED] Pushed accuknox/kubearmor:base"
    exit 0
fi
