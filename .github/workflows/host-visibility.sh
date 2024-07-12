#!/bin/bash

# Edit the daemonset to add the -enableKubeArmorHostPolicy=true flag
# kubectl edit daemonset -n kubearmor <<EOF
# /args:/a \
#         - -enableKubeArmorHostPolicy=true
# EOF

kubectl get daemonset -n kubearmor -o yaml > daemonset.yaml
sed -i '/args:/a \          - -enableKubeArmorHostPolicy=true' daemonset.yaml
sed -i '/args:/a \          - -test.coverprofile=coverage2.out' daemonset.yaml
sed -i '/args:/a \          - -coverageTest=false' daemonset.yaml
kubectl apply -f daemonset.yaml

sleep 1m

# Apply annotations to the node
NODE_NAME=$(kubectl get nodes -o=jsonpath='{.items[0].metadata.name}')
kubectl annotate node $NODE_NAME "kubearmorvisibility=process,file,network,capabilities"
kubectl get no -o wide