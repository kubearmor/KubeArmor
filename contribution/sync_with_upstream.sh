#!/bin/bash
# Copyright 2021 Authors of KubeArmor
# SPDX-License-Identifier: Apache-2.0


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
