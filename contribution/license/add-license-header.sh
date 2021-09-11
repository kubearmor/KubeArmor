#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

echo "Installing addlicense tool"
go get -u github.com/google/addlicense

if [ -z $1 ]; then
        GIT_ROOT=$(git rev-parse --show-toplevel)
        echo "No Arguement Supplied, Checking and Fixing all files from project root"
        addlicense -f license.header -v $GIT_ROOT/**/*.go $GIT_ROOT/**/*.sh
        echo "Done"
else
        addlicense -f license.header -v $1
        echo "Done"
fi
