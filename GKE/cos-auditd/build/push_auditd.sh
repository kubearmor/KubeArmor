#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# push kubearmor/kubearmor-cos-auditd

echo "[INFO] Pushing kubearmor/kubearmor-cos-auditd:$VERSION"
docker push kubearmor/kubearmor-cos-auditd:$VERSION

if [ $? == 0 ]; then
    echo "[PASSED] Pushed kubearmor/kubearmor-cos-auditd:$VERSION"
    exit 0
else
    echo "[FAILED] Failed to push kubearmor/kubearmor-cos-auditd:$VERSION"
    exit 1
fi
