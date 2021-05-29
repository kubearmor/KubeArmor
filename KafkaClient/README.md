# Kafka Client

Kafka client collects the messages, alerts, and system logs from KubeArmor and pushes them to the given Kafka system with the corresponding topics.

## Kafka Deployment

If you do not have a pre-installed Kafka system, you can quickly set up the Kafka system.

```
$ cd KafkaClient/deployments/kafka
(kafka) $ kubectl create namespace kubearmor
(kafka) $ kubectl apply -f kafka-crd.yaml
(kafka) $ kubectl apply -f kafka-deployment.yaml
(kafka) $ kubectl apply -f kafka-volume.yaml
```

Wait for the completed deployments of Kafka pods. It will take a couple of minutes.

```
kubearmor     kafka-cluster-entity-operator-5544dc6545-wtsqn   3/3     Running
kubearmor     kafka-cluster-kafka-0                            1/1     Running
kubearmor     kafka-cluster-zookeeper-0                        1/1     Running
kubearmor     strimzi-cluster-operator-6c7b6c4c6-ktgs8         1/1     Running
```

## Kafka Client Deployment

If the Kafka system is ready, you can simply deploy the Kafka client for KubeArmor.

```
$ cd KafkaClient/deployments
(deployments) $ kubectl apply -f client-deployment.yaml
```
