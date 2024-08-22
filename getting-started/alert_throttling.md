# Alert Throttling

Alert throttling is necessary to prevent overwhelming recipients with a flood of notifications. KubeArmor may bombard users with excessive alerts, leading to alert fatigue, where users become desensitized to notifications. Current throttling implementation is based on the frequency of the alerts. 

> **Note** Alert Throttling is done per container, it's not system wide.

### Usage

Throttling conditions can be configured through the config map, `kubearmor-config` or `KubeArmorConfig` object in case of deployment through operator.

Three configurable conditions for throttling are:

1. enabling/disabling alert throttling, by default alert throttling will be enabled. In order to disable throttling we need to set `alertThrottling` to `false`.

2. set the threshold frequency for the alerts generated, by default it is set to `10` alerts(after enabling throttling), which means 10 alerts would be allowed to be generated per second. After the threshold frequency is crossed an alert will be generated which will notify that threshold frequency is crossed and for next few seconds we will not recieve alerts for this container. In order to set threshold frequency we need to set `maxAlertPerSec` to an int value, which decribes the number of maximum alerts that could be generated per sec.

3. set the timer for throttling, which means for how many seconds we want alerts to be stopped after it crossed the threshold frequency, by default it is set to `30` seconds(after enabling throttling). After the threshold frequency is crossed an alert will be generated which will notify that threshold frequency is crossed. In order to set the throttling timer we need to set `throttleSec` to an int value, which decribes the number of seconds for which subsequent alerts would be dropped.

> **Note** Throttling will be done per container, therefore, threshold frequency will be calculated per container. If threshold frequency is crossed for one conatiner other containers will still provide alerts unless they also cross the threshold frequency.

Throttling alert after crossing the threshold frequency for a `wordpress` container will look like:
```
ClusterName: default
HostName: prateek
NamespaceName: wordpress-mysql
PodName: wordpress-586468bf4f-8bf6x
Labels: app=wordpress
ContainerName: wordpress
ContainerID: a4e3d52aeda8a0256d3c8ad819ec1bc6b61e4fa6f6d68858196d5195b5765d9f
ContainerImage: docker.io/library/wordpress:4.8-apache@sha256:6216f64ab88fc51d311e38c7f69ca3f9aaba621492b4f1fa93ddf63093768845
Type: SystemEvent
Operation: AlertThreshold
Enforcer: BPFLSM
Result: Passed
DroppingAlertsInterval: 30
MaxAlertsPerSec: 2
Owner: map[Name:wordpress Namespace:wordpress-mysql Ref:Deployment]
PPID: 0
UID: 0
```