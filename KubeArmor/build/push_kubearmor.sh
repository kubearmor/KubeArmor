#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

[[ "$REPO" == "" ]] && REPO="kubearmor/kubearmor"

VERSION=latest

# check version
if [ ! -z $1 ]; then
    VERSION="$1"
fi

# push $REPO
echo "[INFO] Pushing $REPO:$VERSION"
docker push $REPO:$VERSION

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $REPO:$VERSION" && exit 1
echo "[PASSED] Pushed $REPO:$VERSION"
exit 0
