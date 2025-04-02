# Testing Changes Guide

If you are interested in contributing to KubeArmor then you probably would be working on following components:
1. KubeArmor Operator
2. KubeArmor Controller
3. KubeArmor Core

You may feel the need to test the changes locally before committing, which will be advantageous for both; Contributors and Reviewers. If you have made any change in Operator or Controller then follow this guide and if changes are in KubeArmor core then follow the [Testing Guide](testing_guide)

# Testing Operator/Controller

1. Build the local docker image of Controller
```text
~/KubeArmor/pkg/KubeArmorController$ make docker-build TAG=latest
```

2. Build the local docker image of Operator
```text
~/KubeArmor/pkg/KubeArmorOperator$ make docker-build
```

3. Generate Artifacts (Resources required for KubeArmor)
```text
~/KubeArmor$ ./KubeArmor/build/build_kubearmor.sh
```
You can skip this if kubearmor images (core and init) are already built!

4. Create Operator from local images
```text
~/KubeArmor$ helm upgrade --install kubearmor-operator ./deployments/helm/KubeArmorOperator -n kubearmor --create-namespace --set kubearmorOperator.image.tag=latest,kubearmorOperator.imagePullPolicy=Never
```

5. Create Controller, Relay Service and other services from local images
```text
~/KubeArmor$ kubectl apply -f pkg/KubeArmorOperator/config/samples/kubearmor-test.yaml --dry-run=client -o json | \
            jq '.spec.kubearmorControllerImage.imagePullPolicy = "Never"' | \
            kubectl apply -f -
```

# Key Points

1. While testing, try to keep the environment clean, like removing all the previous images and deleting the `kubearmor` namespaces.

2. These steps are for building both operator and controller but it may be possible that you just want to rebuild only one of them.

3. After building operator and controller locally, run the automated `ginkgo tests` by following the steps from [Testing Guide](testing_guide)

4. Tests may fail due to flakiness! we are trying our best to reduce flakiness, so do manual testing also and add screenshots/videos to the pull request.