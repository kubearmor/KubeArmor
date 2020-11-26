#!/bin/bash

if [ -z $1 ]; then
    echo "[INFO] Pushing kubearmor/kubearmor:latest"
    docker push kubearmor/kubearmor:latest
else
    echo "[INFO] Pushing kubearmor/kubearmor:$1"
    docker push kubearmor/kubearmor:$1
fi

if [ $? == 0 ]; then
    echo "[PASSED] Pushed the KubeArmor image"
    exit 0
else
    echo "[FAILED] Failed to push the KubeArmor image"
    exit 1
fi
