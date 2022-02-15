#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

if [ $# -ne 4 ]; then
    echo "Usage: $0 subject_path object_path directory(true|false) recursive(true|false)"
    exit 1
fi

SUBJECT_PATH=$1
OBJECT_PATH=$2

DIRECTORY=$3
RECURSIVE=$4

if [ "$SUBJECT_PATH" == "-" ]; then
    if [ "$DIRECTORY" == "true" ]; then
        if [ "$RECURSIVE" == "true" ]; then
            find $OBJECT_PATH \( -type f -o -type l \) -exec restorecon -v -F {} \;
            if [ $? != 0 ]; then
                exit 1
            fi
        else # current directory only
            find $OBJECT_PATH -maxdepth 1 \( -type f -o -type l \) -exec restorecon -v -F {} \;
            if [ $? != 0 ]; then
                exit 1
            fi
        fi
    else # file
        restorecon -v -F $OBJECT_PATH
        if [ $? != 0 ]; then
            exit 1
        fi
    fi
else # fromSource
    if [ "$DIRECTORY" == "true" ]; then
        if [ "$RECURSIVE" == "true" ]; then
            restorecon -v -F $SUBJECT_PATH
            if [ $? != 0 ]; then
                exit 1
            fi

            find $OBJECT_PATH \( -type f -o -type l \) -exec restorecon -v -F {} \;
            if [ $? != 0 ]; then
                exit 1
            fi
        else # current directory only
            restorecon -v -F $SUBJECT_PATH
            if [ $? != 0 ]; then
                exit 1
            fi

            find $OBJECT_PATH -maxdepth 1 \( -type f -o -type l \) -exec restorecon -v -F {} \;
            if [ $? != 0 ]; then
                exit 1
            fi
        fi
    else # file
        restorecon -v -F $SUBJECT_PATH
        if [ $? != 0 ]; then
            exit 1
        fi

        restorecon -v -F $OBJECT_PATH
        if [ $? != 0 ]; then
            exit 1
        fi
    fi
fi

exit 0
