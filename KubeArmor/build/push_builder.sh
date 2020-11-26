#!/bin/bash

echo "[INFO] Pushing kubearmor/kubearmor:base"
docker push kubearmor/kubearmor:base

if [ $? == 0 ]; then
    echo "[PASSED] Pushed the base image"
    exit 0
else
    echo "[FAILED] Failed to push the base image"
    exit 1
fi
