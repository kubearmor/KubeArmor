#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Authors of KubeArmor

BASE_DIR=`dirname $(realpath "$0")`/../..
cd $BASE_DIR
[[ "$REPO" == "" ]] && REPO="kubearmor/kubearmor-relay-server"
[[ "$PLATFORMS" == "" ]] && PLATFORMS="linux/amd64,linux/arm64/v8"

# check version
VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

echo "[INFO] Pushing $REPO:$VERSION"
docker buildx build --metadata-file kubearmor-relay-server.json --platform $PLATFORMS --build-arg VERSION=$VERSION --push -t $REPO:$VERSION -f $BASE_DIR/pkg/KubeArmorRelayServer/Dockerfile .

if [ $? != 0 ]; then
    echo "[FAILED] Failed to push $REPO:$VERSION"
    exit 1
fi
echo "[PASSED] Pushed $REPO:$VERSION"
