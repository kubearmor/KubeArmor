#!/bin/bash

# push the image to Docker Hub

if [ -z $1 ]; then
    echo "[INFO] Pushing accuknox/kubearmor:latest"
    docker push accuknox/kubearmor:latest
else
    echo "[INFO] Pushing accuknox/kubearmor:$1"
    docker push accuknox/kubearmor:$1
fi

if [ $? == 0 ]; then
    echo "[PASSED] Pushed the KubeArmor image"
    exit 0
else
    echo "[FAILED] Failed to push the KubeArmor image"
    exit 1
fi
