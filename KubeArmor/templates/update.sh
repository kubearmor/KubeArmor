#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

if [ $# -ne 6 ]; then
    echo "Usage: $0 subject_label subject_path object_label object_path directory(true|false) recursive(true|false)"
    exit 1
fi

SUBJECT_LABEL=$1
SUBJECT_PATH=$2

OBJECT_LABEL=$3
OBJECT_PATH=$4

DIRECTORY=$5
RECURSIVE=$6

if [ "$SUBJECT_PATH" == "-" ]; then
    if [ "$DIRECTORY" == "true" ]; then
        if [ "$RECURSIVE" == "true" ]; then
            find $OBJECT_PATH \( -type f -o -type l \) -exec chcon -t $OBJECT_LABEL {} \;
            if [ $? != 0 ]; then
                exit 1
            fi
        else # current directory only
            find $OBJECT_PATH -maxdepth 1 \( -type f -o -type l \) -exec chcon -t $OBJECT_LABEL {} \;
            if [ $? != 0 ]; then
                exit 1
            fi
        fi
    else # file
        chcon -t $OBJECT_LABEL $OBJECT_PATH
        if [ $? != 0 ]; then
            exit 1
        fi
    fi
else # fromSource
    if [ "$DIRECTORY" == "true" ]; then
        if [ "$RECURSIVE" == "true" ]; then
            chcon -t $SUBJECT_LABEL $SUBJECT_PATH
            if [ $? != 0 ]; then
                exit 1
            fi

            find $OBJECT_PATH \( -type f -o -type l \) -exec chcon -t $OBJECT_LABEL {} \;
            if [ $? != 0 ]; then
                exit 1
            fi
        else # current directory only
            chcon -t $SUBJECT_LABEL $SUBJECT_PATH
            if [ $? != 0 ]; then
                exit 1
            fi

            find $OBJECT_PATH -maxdepth 1 \( -type f -o -type l \) -exec chcon -t $OBJECT_LABEL {} \;
            if [ $? != 0 ]; then
                exit 1
            fi
        fi
    else # file
        chcon -t $SUBJECT_LABEL $SUBJECT_PATH
        if [ $? != 0 ]; then
            exit 1
        fi

        chcon -t $OBJECT_LABEL $OBJECT_PATH
        if [ $? != 0 ]; then
            exit 1
        fi
    fi
fi

exit 0
