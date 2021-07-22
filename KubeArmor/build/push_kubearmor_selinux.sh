#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# push kubearmor/kubearmor-selinux

echo "[INFO] Pushing kubearmor/kubearmor-selinux:$VERSION"
docker push kubearmor/kubearmor-selinux:$VERSION

if [ $? != 0 ]; then
    echo "[FAILED] Failed to push kubearmor/kubearmor-selinux:$VERSION"
    exit 1
else
    echo "[PASSED] Pushed kubearmor/kubearmor-selinux:$VERSION"
    exit 0
fi
