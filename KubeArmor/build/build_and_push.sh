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

KBA_BUILD=`dirname $(realpath "$0")`
cd $KBA_BUILD

if [ -z $1 ]; then
    echo "$0 [VERSION]"
    exit
fi

./build_kubearmor.sh $1
./push_kubearmor.sh $1
