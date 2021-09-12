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

KBA_HOME=`dirname $(realpath "$0")`/..
cd $KBA_HOME

# add upstream if it doesn't exist
git remote -v | grep kubearmor
if [ $? != 0 ]; then
	git remote add upstream https://github.com/kubearmor/KubeArmor.git
fi

# fetch upstream
git fetch upstream

# switch to master
git checkout master

# merge upstream/master
git merge upstream/master

# push to my repo
git push origin master
