#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

[[ "$REPO" == "" ]] && REPO="kranurag78/kubearmor"

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

# push $REPO-init
echo "[INFO] Pushing $REPO-init:$VERSION"
docker push $REPO-init:$VERSION

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $REPO-init:$VERSION" && exit 1
echo "[PASSED] Pushed $REPO-init:$VERSION"

exit 0
