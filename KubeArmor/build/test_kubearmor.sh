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

ARMOR_HOME=`dirname $(realpath "$0")`/../..

# move to KubeArmor
cd $ARMOR_HOME/KubeArmor

# check go-fmt
make gofmt
if [ $? != 0 ]; then
    echo "[FAILED] Failed to check go-fmt"
    exit 1
fi

# check go-lint
make golint
if [ $? != 0 ]; then
    echo "[FAILED] Failed to check go-lint"
    exit 1
fi

# check go-sec
make gosec
if [ $? != 0 ]; then
    echo "[FAILED] Failed to check go-sec"
    exit 1
fi

# test KubeArmor
make testall
if [ $? != 0 ]; then
    echo "[FAILED] Failed to test KubeArmor"
    exit 1
fi

# compile KubeArmor
make clean && make
if [ $? != 0 ]; then
    echo "[FAILED] Failed to compile KubeArmor"
    exit 1
fi

KPROXY=$(ps -ef | grep "kubectl proxy" | wc -l)
if [ $KPROXY == 1 ]; then
    # run kube-proxy
    kubectl proxy &
fi

# move to tests
cd $ARMOR_HOME/tests

# test scenarios
./test-scenarios-local.sh

RESULT=$?

if [ $KPROXY == 1 ]; then
    # stop kube-proxy
    ps -ef | grep "kubectl proxy" | grep -v grep | awk '{print $2}' | xargs -I {} kill -9 {}
fi

if [ $RESULT != 0 ]; then
    exit 1
fi

exit 0
