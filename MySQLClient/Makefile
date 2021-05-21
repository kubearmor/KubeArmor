CURDIR=$(shell pwd)
CLUSTERIP=$(shell kubectl get svc -A | grep mysql | awk '{print $$4}')

DB_HOST=$(CLUSTERIP):3306
DB_USER=kubearmor
DB_PASSWD=kubearmor-passwd
DB_NAME=kubearmor-db

TABLE_MSG=messages
TABLE_ALERT=alerts
TABLE_LOG=syslogs

.PHONY: build
build:
	cd $(CURDIR); go build -o kubearmor-mysql-client main.go

.PHONY: run
run: $(CURDIR)/kubearmor-mysql-client
	cd $(CURDIR); DB_HOST=$(DB_HOST) DB_USER=$(DB_USER) DB_PASSWD=$(DB_PASSWD) DB_NAME=$(DB_NAME) TABLE_MSG=$(TABLE_MSG) TABLE_ALERT=$(TABLE_ALERT) TABLE_LOG=$(TABLE_LOG) ./kubearmor-mysql-client

.PHONY: dropTables
dropTables: $(CURDIR)/kubearmor-mysql-client
	cd $(CURDIR); DB_HOST=$(DB_HOST) DB_USER=$(DB_USER) DB_PASSWD=$(DB_PASSWD) DB_NAME=$(DB_NAME) TABLE_MSG=$(TABLE_MSG) TABLE_ALERT=$(TABLE_ALERT) TABLE_LOG=$(TABLE_LOG) ./kubearmor-mysql-client -dropTables

.PHONY: clean
clean:
	cd $(CURDIR); sudo rm -f kubearmor-mysql-client
	cd $(CURDIR); find . -name go.sum | xargs -I {} rm -f {}
