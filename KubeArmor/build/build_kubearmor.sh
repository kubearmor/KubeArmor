#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

[[ "$REPO" == "" ]] && REPO="kubearmor/kubearmor"

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

VERSION=latest

# check version
if [ ! -z $1 ]; then
    VERSION=$1
fi

# remove old images
docker images | grep kubearmor | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null
echo "[INFO] Removed existing $REPO images"

# set DTAG and LABEL
DTAG="-t $REPO:$VERSION"
DTAGINI="-t $REPO-init:$VERSION"
unset LABEL
[[ "$GITHUB_SHA" != "" ]] && LABEL="--label github_sha=$GITHUB_SHA"

# build a new image
echo "[INFO] Building $DTAG"
cd $ARMOR_HOME/..; docker build $DTAG --target kubearmor . $LABEL
echo "[INFO] Building $DTAGINI"
cd $ARMOR_HOME/..; docker build $DTAGINI --target kubearmor-init . $LABEL

if [ $? != 0 ]; then
    echo "[FAILED] Failed to build $REPO:$VERSION"
    exit 1
fi
echo "[PASSED] Built $REPO:$VERSION"

exit 0
