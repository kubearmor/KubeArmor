#!/bin/bash

# remove old images
docker images | grep kubearmor | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

# build a base
docker build -t kubearmor/kubearmor:base . -f Dockerfile.builder

if [ $? == 0 ]; then
    echo "[PASSED] Built kubearmor/kubearmor:base"
    exit 0
else
    echo "[FAILED] Failed to build kubearmor/kubearmor:base"
    exit 1
fi
