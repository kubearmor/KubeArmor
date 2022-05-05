# Kubernetes Controllers

## KubeArmorPolicy

KubeArmorPolicy provides the CRD for container policy specifications and the controller that verifies policies given by a user through kubectl.

```
cd KubeArmorPolicy
make              # compile the kubearmor-policy-controller-manager
make manifests    # create the KubeArmorPolicy CRD
make docker-build # create a local image for the kubearmor-policy-controller-manager
make deploy       # deploy the created local image for testing
make delete       # delete the controller deployed for testing
```

## KubeArmorHostPolicy

KubeArmorHostPolicy provides the CRD for host policy specifications and the controller that verifies host policies given by a user through kubectl.

```
cd KubeArmorHostPolicy
make              # compile the kubearmor-host-policy-controller-manager
make manifests    # create the KubeArmorHostPolicy CRD
make docker-build # create a local image for the kubearmor-host-policy-controller-manager
make deploy       # deploy the created local image for testing
make delete       # delete the controller deployed for testing
```

## KubeArmorAnnotation

KubeArmorAnnotation provides the admission controller that automatically adds the annotations for kubearmor-policy, kubearmor-visibilities, and apparmor.

```
cd KubeArmorAnnotation
make                     # compile the kubearmor-annotation-manager
make docker-build        # create a local image for the kubearmor-annotation-manager
make deploy-cert-manager # deploy cert-manager
make deploy              # deploy the created local image for testing
make delete              # delete the controller deployed for testing
make delete-cert-manager # delete cert-manager
```
