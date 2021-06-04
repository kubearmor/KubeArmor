CURDIR=$(shell pwd)

CLUSTER_IP=$(shell kubectl -n kubearmor get svc | grep kafka-bootstrap | awk '{print $$3}')
KAFKA_BOOTSTRAP_SERVER=$(CLUSTER_IP):9092

TOPIC_MSG=kubearmor-messages
TOPIC_ALERT=kubearmor-alerts
TOPIC_LOG=kubearmor-syslogs

.PHONY: build
build:
	cd $(CURDIR); go mod tidy
	cd $(CURDIR); go build -o kubearmor-kafka-client main.go

.PHONY: run
run: $(CURDIR)/kubearmor-kafka-client
	cd $(CURDIR); KAFKA_BOOTSTRAP_SERVER=$(KAFKA_BOOTSTRAP_SERVER) TOPIC_MSG=$(TOPIC_MSG) TOPIC_ALERT=$(TOPIC_ALERT) TOPIC_LOG=$(TOPIC_LOG) ./kubearmor-kafka-client

.PHONY: build-image
build-image:
	cd $(CURDIR); cp -r ../protobuf .
	cd $(CURDIR); docker build -t accuknox/kubearmor-kafka-client:latest .
	cd $(CURDIR); rm -rf protobuf

.PHONY: push-image
push-image:
	cd $(CURDIR); docker push accuknox/kubearmor-kafka-client:latest

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -f kubearmor-kafka-client
	cd $(CURDIR); find . -name go.sum | xargs -I {} rm -f {}
