#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026  Authors of KubeArmor

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

exit 0
