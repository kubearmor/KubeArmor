# Kubernetes Controllers

## KubeArmorController

KubeArmorController provides CRDs for container, host policy specifications and also verifies the policies given by a user through kubectl. It also provides the admission controller that automatically adds the annotations for kubearmor-policy, kubearmor-visibilities, and apparmor.

```
cd KubeArmorController
make              # compile the kubearmor-controller
make manifests    # create the KubeArmorPolicy and KubeArmorHostPolicy CRD, WebhookConfiguration and ClusterRole
make docker-build # create a local image for the kubearmor-controller
make deploy       # deploy the created local image for testing
make delete       # delete the controller deployed for testing
```
