# Kubernetes Controllers

## KubeArmorOperator

KubeArmorOperator provides CRDs for container, cluster, host and network policy, and kubearmorconfig specifications and also verifies the policies given by a user through kubectl. It also provides the admission controller that automatically adds the annotations for kubearmor-policy, kubearmor-visibilities, and apparmor.

```
cd KubeArmorOperator
make              # compile the kubearmor-operator
make manifests    # create the KubeArmorConfig, KubeArmorPolicy, KubeArmorClusterPolicy, KubeArmorHostPolicy and KubeArmorNetworkPolicy CRD, WebhookConfiguration and ClusterRole
make docker-build # create a local image for the kubearmor-operator
make deploy       # deploy the created local image for testing
make delete       # delete the controller deployed for testing
```
