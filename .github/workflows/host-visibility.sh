#!/bin/bash
// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

DAEMONSET_NAME=$(kubectl get daemonset -n kubearmor -o jsonpath='{.items[0].metadata.name}')

kubectl patch daemonset $DAEMONSET_NAME -n kubearmor --type='json' -p='[
            {
              "op": "add",
              "path": "/spec/template/spec/containers/0/args/-",
              "value": "-enableKubeArmorHostPolicy"
            }
          ]'

sleep 16

# Apply annotations to the node
NODE_NAME=$(kubectl get nodes -o=jsonpath='{.items[0].metadata.name}')
kubectl annotate node $NODE_NAME "kubearmorvisibility=process,file,network,capabilities"
kubectl get no -o wide