#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 Authors of KubeArmor

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

BPF_HOME=`dirname $(realpath "$0")`/..

if command -v sudo &> /dev/null
then
    SUDO="sudo"
fi

SYSCALL=${1#*/}

if ! $SUDO ./syscheck $1 ; then
    echo "Disabling $SYSCALL ..."
    echo "$SYSCALL" >> ignore.lst
else
    echo "Enabling syscall $SYSCALL"
    grep "// CFlag=.*$" "$1.c" | sed -E "s/.*?=(.*?)$/\1/" >> cflags.lst
fi
