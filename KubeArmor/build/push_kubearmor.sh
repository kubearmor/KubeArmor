#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

[[ "$REPO" == "" ]] && REPO="kubearmor/kubearmor"

[[ "$PLATFORMS" == "" ]] && PLATFORMS="linux/amd64"

VERSION=latest

# check version
if [ ! -z $1 ]; then
    VERSION="$1"
fi

realpath() {
    CURR=$PWD

    cd "$(dirname "$0")"
    LINK=$(readlink "$(basename "$0")")

    while [ "$LINK" ]; do
        cd "$(dirname "$LINK")"
        LINK=$(readlink "$(basename "$1")")
    done

    REALPATH="$PWD/$(basename "$1")"
    echo "$REALPATH"

    cd $CURR
}

ARMOR_HOME=`dirname $(realpath "$0")`/..
cd $ARMOR_HOME/build
pwd

# push $REPO
echo "[INFO] Pushing $REPO:$VERSION"
cd $ARMOR_HOME/..; docker buildx build --platform $PLATFORMS -t $REPO:$VERSION --push .

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $REPO:$VERSION" && exit 1
echo "[PASSED] Pushed $REPO:$VERSION"

# push $REPO-init
echo "[INFO] Pushing $REPO-init:$VERSION"
cd $ARMOR_HOME/..; docker buildx build --platform $PLATFORMS -t $REPO-init:$VERSION --push .

[[ $? -ne 0 ]] && echo "[FAILED] Failed to push $REPO-init:$VERSION" && exit 1
echo "[PASSED] Pushed $REPO-init:$VERSION"

exit 0
