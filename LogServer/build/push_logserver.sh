#!/bin/bash

# push the image to Docker Hub

if [ -z $1 ]; then
    echo "[INFO] Pushing accuknox/kubearmor-logserver:latest"
    docker push accuknox/kubearmor-logserver:latest
else
    echo "[INFO] Pushing accuknox/kubearmor-logserver:$1"
    docker push accuknox/kubearmor-logserver:$1
fi

if [ $? == 0 ]; then
    echo "[PASSED] Pushed the KubeArmor-LogServer image"
    exit 0
else
    echo "[FAILED] Failed to push the KubeArmor-LogServer image"
    exit 1
fi
