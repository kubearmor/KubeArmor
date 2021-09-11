#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

VERSION=latest

# check version
if [ ! -z $1 ]; then
    VERSION=$1
fi

# push kubearmor/kubearmor
echo "[INFO] Pushing kubearmor/kubearmor:$VERSION"
docker push kubearmor/kubearmor:$VERSION

if [ $? != 0 ]; then
    echo "[FAILED] Failed to push kubearmor/kubearmor:$VERSION"
    exit 1
else
    echo "[PASSED] Pushed kubearmor/kubearmor:$VERSION"
    exit 0
fi
