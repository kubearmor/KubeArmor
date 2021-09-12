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

CHECK_HOME=`dirname $(realpath "$0")`/system

$CHECK_HOME/check_kernel_version.sh
if [ $? != 0 ]; then
    exit 1
fi

$CHECK_HOME/check_bpf.sh
if [ $? != 0 ]; then
    exit 1
fi

$CHECK_HOME/check_lsm.sh
if [ $? != 0 ]; then
    exit 1
fi

exit 0
