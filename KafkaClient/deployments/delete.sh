#!/bin/bash

NAMESPACE=kubearmor

KUBEARMOR_CLIENT=$(kubectl get pods -n $NAMESPACE | grep kafka-client | wc -l)
if [ $KUBEARMOR_CLIENT != 0 ]; then
    kubectl -n $NAMESPACE delete -f client-deployment.yaml
fi

KUBEARMOR_KAFKA=$(kubectl get pods -n $NAMESPACE | grep kafka-cluster | wc -l)
if [ $KUBEARMOR_KAFKA != 0 ]; then
    kubectl -n $NAMESPACE delete -f kafka/kafka-volume.yaml
    sleep 10
    kubectl -n $NAMESPACE delete -f kafka/kafka-deployment.yaml
    kubectl delete -f kafka/kafka-crd.yaml
fi

KUBEARMOR_NS=$(kubectl get pods -n $NAMESPACE | wc -l)
if [ $KUBEARMOR_NS == 0 ]; then
    kubectl delete namespace $NAMESPACE
fi

find . -name *.yaml -exec sed -i "s/namespace: $NAMESPACE/namespace: kubearmor/g" {} \;
