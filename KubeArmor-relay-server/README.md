# KubeArmor Relay Server

KubeArmor's relay server collects the messages, alerts, and system logs generated from KubeArmor in each node, and then it allows other logging systems to simply collect all of the logs through the service ('kubearmor.kube-system.svc') of the relay server.

By default, the relay server is deployed with KubeArmor.
