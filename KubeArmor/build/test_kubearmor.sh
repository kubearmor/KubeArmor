#!/bin/bash

ARMOR_HOME=`dirname $(realpath "$0")`/../..

# move to KubeArmor
cd $ARMOR_HOME/KubeArmor

# test KubeArmor
make testall

if [ $? != 0 ]; then
    echo "[FAILED] Failed to test KubeArmor"
    exit 1
fi

# compile KubeArmor
make clean && make

if [ $? != 0 ]; then
    echo "[FAILED] Failed to compile KubeArmor"
    exit 1
fi

KPROXY=$(ps -ef | grep "kubectl proxy" | wc -l)
if [ $KPROXY == 1 ]; then
    # run kube-proxy
    kubectl proxy &
fi

# move to tests
cd $ARMOR_HOME/tests

# test scenarios
./test-scenarios-local.sh -y

RESULT=$?

if [ $KPROXY == 1 ]; then
    # stop kube-proxy
    ps -ef | grep "kubectl proxy" | grep -v grep | awk '{print $2}' | xargs -I {} kill {}
fi

if [ $RESULT != 0 ]; then
    exit 1
fi

exit 0
