#!/bin/bash

NAMESPACE=kubearmor

find . -name *.yaml -exec sed -i "s/namespace: kubearmor/namespace: $NAMESPACE/g" {} \;

KUBEARMOR_NS=$(kubectl get ns | grep $NAMESPACE | wc -l)
if [ $KUBEARMOR_NS == 0 ]; then
    kubectl create namespace $NAMESPACE
fi

KUBEARMOR_KAFKA=$(kubectl get pods -n $NAMESPACE | grep kafka-cluster | wc -l)
if [ $KUBEARMOR_KAFKA == 0 ]; then
    kubectl apply -f kafka/kafka-crd.yaml
    kubectl -n $NAMESPACE apply -f kafka/kafka-deployment.yaml
    sleep 10
    kubectl -n $NAMESPACE apply -f kafka/kafka-volume.yaml
fi

KUBEARMOR_CLIENT=$(kubectl get pods -n $NAMESPACE | grep kafka-client | wc -l)
if [ $KUBEARMOR_CLIENT == 0 ]; then
    kubectl -n $NAMESPACE apply -f client-deployment.yaml
fi
