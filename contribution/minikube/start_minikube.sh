#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

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

MINIKUBE_DIR=`dirname $(realpath "$0")`

# download minikube iso
wget -O $MINIKUBE_DIR/minikube.iso https://github.com/kubearmor/kastore/blob/main/iso/minikube/minikube.iso?raw=true

# start minikube with a specific image

minikube start --iso-url=file://$MINIKUBE_DIR/minikube.iso --cpus 4 --memory 4096 --cni flannel
