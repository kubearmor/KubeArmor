#!/bin/bash

# remove old images

docker images | grep kubearmor | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

# build a base image

echo "[INFO] Building accuknox/kubearmor:base"
docker build -t accuknox/kubearmor:base . -f Dockerfile.builder

if [ $? == 0 ]; then
    echo "[PASSED] Built accuknox/kubearmor:base"
else
    echo "[FAILED] Failed to build accuknox/kubearmor:base"
    exit 1
fi

# push the base image to Docker Hub

echo "[INFO] Pushing accuknox/kubearmor:base"
docker push accuknox/kubearmor:base

if [ $? == 0 ]; then
    echo "[PASSED] Pushed the base image"
    exit 0
else
    echo "[FAILED] Failed to push the base image"
    exit 1
fi
