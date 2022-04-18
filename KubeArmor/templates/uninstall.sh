#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

if [ -z $1 ]; then
    echo "Usage: $0 [ all | SELinux module ]"
    exit 1
fi

MOD=$1

if [ "$MOD" == "all" ]; then
    semanage module -l | grep karmor > /dev/null 2>&1
    if [ $? == 0 ]; then
        semanage module -l | grep karmor | awk '{print $1}' | while read line;
        do
            # remove SELinux module
            semodule -r $line
            if [ $? != 0 ]; then
                echo "Failed to uninstall $line SELinux module"
                exit 1
            fi
        done
    fi
else
    semanage module -l | grep "$MOD " > /dev/null 2>&1
    if [ $? == 0 ]; then
        # remove SELinux module
        semodule -r $MOD
        if [ $? != 0 ]; then
            echo "Failed to uninstall $MOD SELinux module"
            exit 1
        fi
    fi
fi

exit 0
