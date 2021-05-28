#!/bin/bash

NAMESPACE=kubearmor

find . -name *.yaml -exec sed -i "s/namespace: kubearmor/namespace: $NAMESPACE/g" {} \;

KUBEARMOR_NS=$(kubectl get ns | grep $NAMESPACE | wc -l)
if [ $KUBEARMOR_NS == 0 ]; then
    kubectl create namespace $NAMESPACE
fi

KUBEARMOR_CLIENT=$(kubectl get pods -n $NAMESPACE | grep log-client | wc -l)
if [ $KUBEARMOR_CLIENT == 0 ]; then
    kubectl -n $NAMESPACE apply -f client-deployment.yaml
fi
