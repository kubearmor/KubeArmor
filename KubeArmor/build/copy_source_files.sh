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

mkdir -p $ARMOR_HOME/build/KubeArmor

# copy files to build
rsync -av $ARMOR_HOME $ARMOR_HOME/build/KubeArmor --exclude build

# copy patch.sh
#cp $ARMOR_HOME/build/patch.sh $ARMOR_HOME/build/KubeArmor/
cp $ARMOR_HOME/build/patch_selinux.sh $ARMOR_HOME/build/KubeArmor/

# copy entrypoint.sh
cp $ARMOR_HOME/build/entrypoint.sh $ARMOR_HOME/build/KubeArmor/

# copy GKE files
cp -r $ARMOR_HOME/../GKE $ARMOR_HOME/build/

# copy protobuf
cp -r $ARMOR_HOME/../protobuf $ARMOR_HOME/build/
