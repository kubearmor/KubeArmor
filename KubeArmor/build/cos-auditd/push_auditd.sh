#!/bin/bash

if [ -z $1 ]; then
    echo "[INFO] Pushing kubearmor/kubearmor-cos-auditd:latest"
    docker push kubearmor/kubearmor-cos-auditd:latest
else
    echo "[INFO] Pushing kubearmor/kubearmor-cos-auditd:$1"
    docker push kubearmor/kubearmor-cos-auditd:$1
fi

if [ $? == 0 ]; then
    echo "[PASSED] Pushed the KubeArmor-COS-Auditd image"
    exit 0
else
    echo "[FAILED] Failed to push the KubeArmor-COS-Auditd image"
    exit 1
fi
