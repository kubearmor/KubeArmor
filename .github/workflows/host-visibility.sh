#!/bin/bash

# Edit the daemonset to add the -enableKubeArmorHostPolicy=true flag
kubectl edit daemonset $(kubectl get daemonset -n kubearmor -o name | grep kubearmor-) -n kubearmor <<EOF
/args:/a \
        - -enableKubeArmorHostPolicy=true
EOF

# Apply annotations to the node
kubectl annotate node kubearmor-dev "kubearmor-visibility=process,file,network,capabilities"
kubectl get no -o wide