#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0

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

AUDITD_PATH=`dirname $(realpath "$0")`
cd $AUDITD_PATH

# check version

VERSION=latest

if [ ! -z $1 ]; then
    VERSION=$1
fi

# remove old images

docker images | grep kubearmor/kubearmor-cos-auditd | awk '{print $3}' | xargs -I {} docker rmi -f {} 2> /dev/null

echo "[INFO] Removed existing kubearmor/kubearmor-cos-auditd images"

# build a new image

echo "[INFO] Building kubearmor/kubearmor-cos-auditd:$VERSION"
docker build -t kubearmor/kubearmor-cos-auditd:$VERSION  .

if [ $? == 0 ]; then
    echo "[PASSED] Built kubearmor/kubearmor-cos-auditd:$VERSION"
    exit 0
else
    echo "[FAILED] Failed to build kubearmor/kubearmor-cos-auditd:$VERSION"
    exit 1
fi
