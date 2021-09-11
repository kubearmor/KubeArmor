#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 Authors of KubeArmor

TIMEOUT=300

for (( ; ; ))
do
    RAW=$(kubectl get pods -n kube-system 2> /dev/null | wc -l)
    if [ $RAW == 0 ]; then
        sleep 1
	continue
    fi

    ALL=`expr $RAW - 1`
    READY=`kubectl get pods -n kube-system | grep Running | wc -l`

    if [ $ALL == $READY ]; then
        sleep 1

        RAW=$(kubectl get pods -n kube-system 2> /dev/null | wc -l)

        ALL=`expr $RAW - 1`
        READY=`kubectl get pods -n kube-system | grep Running | wc -l`

        if [ $ALL == $READY ]; then
            echo "[PASSED] Checked Kubernetes"
            exit 0
        fi
    fi

    TIMEOUT=`expr $TIMEOUT - 1`
    if [ $TIMEOUT == 0 ]; then
        echo "[FAILED] Reached to TIMEOUT"
        exit 1
    fi

    sleep 1
done
