# Coverage in Kubernetes tests

Use this guide to generate and collect Go coverage when running KubeArmor as a DaemonSet in a Kubernetes cluster. The steps mirror the CI configuration.

Prerequisites
- A working Kubernetes cluster with kubectl and Helm configured
- jq and paste installed on your host
- Go toolchain installed (for go tool cover)

1) Build coverage-enabled KubeArmor images
```text
# From repo root
export IS_COVERAGE=true
./KubeArmor/build/build_kubearmor.sh
```

2) Install the KubeArmor Operator
```text
helm upgrade --install kubearmor-operator ./deployments/helm/KubeArmorOperator \
  -n kubearmor --create-namespace \
  --set kubearmorOperator.image.tag=latest \
  --set kubearmorOperator.annotateExisting=true
kubectl wait --for=condition=ready --timeout=5m -n kubearmor pod -l kubearmor-app=kubearmor-operator
```

3) Deploy KubeArmor using the coverage sample
```text
kubectl apply -f pkg/KubeArmorOperator/config/samples/kubearmor-coverage.yaml
kubectl wait -n kubearmor --timeout=5m --for=jsonpath='{.status.phase}'=Running kubearmorconfigs/kubearmorconfig-test
```

4) Patch the DaemonSet to write coverage to a mounted volume
```text
sleep 10
DAEMONSET_NAME=$(kubectl get daemonset -n kubearmor -o jsonpath='{.items[0].metadata.name}')

echo "Patching DaemonSet: $DAEMONSET_NAME"
kubectl patch daemonset "$DAEMONSET_NAME" -n kubearmor --type='json' -p='[
  {
    "op": "add",
    "path": "/spec/template/spec/volumes/-",
    "value": {
      "name": "coverage-storage",
      "hostPath": {
        "path": "/coverage",
        "type": "DirectoryOrCreate"
      }
    }
  },
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/volumeMounts/-",
    "value": {
      "mountPath": "/coverage",
      "name": "coverage-storage"
    }
  },
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/args/-",
    "value": "-test.coverprofile=/coverage/coverage_k8s_local.out"
  }
]'
```

5) Identify the KubeArmor Pod name
```text
DAEMONSET_NAME=$(kubectl get daemonset -n kubearmor -o jsonpath='{.items[0].metadata.name}')
LABEL_SELECTOR=$(kubectl get daemonset "$DAEMONSET_NAME" -n kubearmor -o jsonpath='{.spec.selector.matchLabels}' | jq -r 'to_entries[] | "\(.key)=\(.value)"' | paste -sd, -)
POD_NAME=$(kubectl get pods -n kubearmor -l "$LABEL_SELECTOR" -o jsonpath='{.items[0].metadata.name}')
echo "POD_NAME=$POD_NAME"
```

6) Run your tests (optional)
- From tests/k8s_env: `make` or `ginkgo ...`

7) Gracefully stop KubeArmor to flush the coverage profile
```text
# Send SIGINT to the KubeArmor process inside the pod
KUBEARMOR_PID=$(kubectl exec "$POD_NAME" -n kubearmor -c kubearmor -- \
  sh -c "ps aux | grep '[k]ubearmor-test' | awk '{print \$2}'")
if [ -n "$KUBEARMOR_PID" ]; then
  kubectl exec "$POD_NAME" -n kubearmor -c kubearmor -- sh -c "kill -2 $KUBEARMOR_PID"
  sleep 10
else
  echo "No KubeArmor process found to kill."
fi
```

8) Copy and inspect the coverage file
```text
# Copy the coverage profile from the pod
kubectl cp -n kubearmor "$POD_NAME":/coverage/coverage_k8s_local.out ./coverage_k8s_local.out

# Summarize coverage
go tool cover -func=./coverage_k8s_local.out
```

Notes
- The coverage sample uses the test images `kubearmor/kubearmor-test:latest` and `kubearmor/kubearmor-test-init:latest` with `imagePullPolicy: Never`. Ensure these images exist locally from step (1).
- The JSON patch mirrors CI and appends `-test.coverprofile` to KubeArmor.
