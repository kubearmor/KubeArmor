CURDIR=$(shell pwd)

CLUSTER_IP=$(shell kubectl get svc -A | grep mysql | awk '{print $$4}')
DB_HOST=$(CLUSTER_IP):3306

DB_NAME=kubearmor-db
DB_USER=kubearmor
DB_PASSWD=kubearmor-passwd

TABLE_MSG=messages
TABLE_ALERT=alerts
TABLE_LOG=syslogs

.PHONY: build
build:
	cd $(CURDIR); go mod tidy
	cd $(CURDIR); go build -o kubearmor-mysql-client main.go

.PHONY: run
run: $(CURDIR)/kubearmor-mysql-client
	cd $(CURDIR); DB_HOST=$(DB_HOST) DB_NAME=$(DB_NAME) DB_USER=$(DB_USER) DB_PASSWD=$(DB_PASSWD) TABLE_MSG=$(TABLE_MSG) TABLE_ALERT=$(TABLE_ALERT) TABLE_LOG=$(TABLE_LOG) ./kubearmor-mysql-client

.PHONY: drop-tables
drop-tables: $(CURDIR)/kubearmor-mysql-client
	cd $(CURDIR); DB_HOST=$(DB_HOST) DB_NAME=$(DB_NAME) DB_USER=$(DB_USER) DB_PASSWD=$(DB_PASSWD) TABLE_MSG=$(TABLE_MSG) TABLE_ALERT=$(TABLE_ALERT) TABLE_LOG=$(TABLE_LOG) ./kubearmor-mysql-client -dropTables

.PHONY: build-image
build-image:
	cd $(CURDIR); cp -r ../protobuf .
	cd $(CURDIR); docker build -t accuknox/kubearmor-mysql-client:latest .
	cd $(CURDIR); rm -rf protobuf

.PHONY: push-image
push-image:
	cd $(CURDIR); docker push accuknox/kubearmor-mysql-client:latest

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -f kubearmor-mysql-client
	cd $(CURDIR); find . -name go.sum | xargs -I {} rm -f {}
