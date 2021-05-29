#!/bin/bash

NAMESPACE=kubearmor

KUBEARMOR_CLIENT=$(kubectl get pods -n $NAMESPACE | grep mysql-client | wc -l)
if [ $KUBEARMOR_CLIENT != 0 ]; then
    kubectl -n $NAMESPACE delete -f client-deployment.yaml
fi

KUBEARMOR_MYSQL=$(kubectl get pods -n $NAMESPACE | grep mysql | wc -l)
if [ $KUBEARMOR_MYSQL != 0 ]; then
    kubectl -n $NAMESPACE delete -f mysql/mysql-deployment.yaml
fi

KUBEARMOR_NS=$(kubectl get pods -n $NAMESPACE | wc -l)
if [ $KUBEARMOR_NS == 0 ]; then
    kubectl delete namespace $NAMESPACE
fi

find . -name *.yaml -exec sed -i "s/namespace: $NAMESPACE/namespace: kubearmor/g" {} \;
