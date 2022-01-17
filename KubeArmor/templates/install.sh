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

CURR_DIR=`dirname $(realpath "$0")`
cd $CURR_DIR

MOD="karmor"

if [ ! -z $1 ]; then
    MOD=$1
fi

# copy karmorX to $MOD
cp karmorX.fc $MOD.fc
cp karmorX.if $MOD.if
cp karmorX.te $MOD.te

# replace karmorX with $MOD
sed -i "s/karmorX/$MOD/g" $MOD.te

# compile and insert selinux module
make -f /usr/share/selinux/devel/Makefile $MOD.pp && semodule -i $MOD.pp

# remove temp files
rm -rf $MOD.fc $MOD.if $MOD.te $MOD.pp tmp
