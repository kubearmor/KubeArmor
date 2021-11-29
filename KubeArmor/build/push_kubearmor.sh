#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

[[ "$REPO" == "" ]] && REPO="kubearmor/kubearmor"
unset PUSH_ALL_TAGS

# check version
if [ ! -z $1 ]; then
    VERSION=":$1"
else
	PUSH_ALL_TAGS="-a"
fi

# push $REPO
echo "[INFO] Pushing $REPO$VERSION"
docker push $PUSH_ALL_TAGS $REPO$VERSION

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $REPO$VERSION" && exit 1
echo "[PASSED] Pushed $REPO$VERSION"
exit 0
