#!/bin/bash

kubectl get daemonset -n kubearmor -o yaml > daemonset.yaml
sed -i '/args:/a \          - -enableKubeArmorHostPolicy' daemonset.yaml
kubectl apply -f daemonset.yaml

sleep 1m

# Apply annotations to the node
NODE_NAME=$(kubectl get nodes -o=jsonpath='{.items[0].metadata.name}')
kubectl annotate node $NODE_NAME "kubearmorvisibility=process,file,network,capabilities"
kubectl get no -o wide