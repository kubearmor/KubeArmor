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

ARMOR_HOME=`dirname $(realpath "$0")`/..

# KubeArmor

cd $ARMOR_HOME/KubeArmor

## == ##

echo "[INFO] Clean up KubeArmor"
echo

make clean

if [ $? != 0 ]; then
    echo
    echo "[FAIL] Failed to clean up KubeArmor"
    exit 1
fi

echo
echo "[PASS] Cleaned up KubeArmor"

## == ##

echo
echo "[INFO] Test KubeArmor"
echo

make testall

if [ $? != 0 ]; then
    echo
    echo "[FAIL] Failed to test KubeArmor"
    exit 1
fi

echo
echo "[PASS] Tested KubeArmor"

## == ##

echo
echo "[INFO] Build KubeArmor"
echo

make

if [ $? != 0 ]; then
    echo
    echo "[FAIL] Failed to build KubeArmor"
    exit 1
fi

echo
echo "[PASS] Built KubeArmor"
exit 0
