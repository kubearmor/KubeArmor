# MySQL Client

MySQL client collects the messages, alerts, and system logs from KubeArmor and stores them in the corresponding tables of the given database.

## MySQL Deployment

If you do not have a pre-installed MySQL database, you can quickly set up the MySQL database.

```
$ cd MySQLClient/deployments/mysql
(mysql) $ kubectl create namespace kubearmor
(mysql) $ kubectl apply -f mysql-deployment.yaml
```

* Default configuration

    ```
    - name: MYSQL_ROOT_PASSWORD
        value: root-passwd
    - name: MYSQL_DATABASE
        value: kubearmor-db
    - name: MYSQL_USER
        value: kubearmor
    - name: MYSQL_PASSWORD
        value: kubearmor-passwd
    ```

    If you want to edit those values, you can edit the YAML file.

## MySQL Client Deployment

If the MySQL database is ready, you can simply deploy the MySQL client for KubeArmor.

```
$ cd MySQLClient/deployments
(deployments) $ kubectl create namespace kubearmor
(deployments) $ kubectl apply -f client-deployment.yaml
```

If you changed the MySQL configuration, you should edit 'client-deployment.yaml' too.

## DB Tables

If the following tables are not in the database, the MySQL client automatically creates them.

1. Messages

    ```
    `id` int NOT NULL AUTO_INCREMENT,
    `timestamp` int NOT NULL,
    `updatedTime` varchar(30) NOT NULL,
    `clusterName` varchar(100) NOT NULL,
    `hostName` varchar(100) NOT NULL,
    `hostIP` varchar(100) NOT NULL,
    `level` varchar(20) NOT NULL,
    `message` varchar(1000) NOT NULL,
    ```

2. Alerts

    ```
	`id` int NOT NULL AUTO_INCREMENT,
	`timestamp` int NOT NULL,
	`updatedTime` varchar(30) NOT NULL,
	`clusterName` varchar(100) NOT NULL,
	`hostName` varchar(100) NOT NULL,
	`namespaceName` varchar(100) NOT NULL,
	`podName` varchar(200) NOT NULL,
	`containerID` varchar(200) NOT NULL,
	`containerName` varchar(200) NOT NULL,
	`hostPid` int NOT NULL,
	`ppid` int NOT NULL,
	`pid` int NOT NULL,
	`uid` int NOT NULL,
	`policyName` varchar(1000) NOT NULL,
	`severity` varchar(100) NOT NULL,
	`tags` varchar(1000) NOT NULL,
	`message` varchar(1000) NOT NULL,
	`type` varchar(20) NOT NULL,
	`source` varchar(4000) NOT NULL,
	`operation` varchar(20) NOT NULL,
	`resource` varchar(4000) NOT NULL,
	`data` varchar(1000) DEFAULT NULL,
	`action` varchar(20) NOT NULL,
	`result` varchar(200) NOT NULL,
    ```

3. System Logs

    ```
	`id` int NOT NULL AUTO_INCREMENT,
	`timestamp` int NOT NULL,
	`updatedTime` varchar(30) NOT NULL,
	`clusterName` varchar(100) NOT NULL,
	`hostName` varchar(100) NOT NULL,
	`namespaceName` varchar(100) NOT NULL,
	`podName` varchar(200) NOT NULL,
	`containerID` varchar(200) NOT NULL,
	`containerName` varchar(200) NOT NULL,
	`hostPid` int NOT NULL,
	`ppid` int NOT NULL,
	`pid` int NOT NULL,
	`uid` int NOT NULL,
	`type` varchar(20) NOT NULL,
	`source` varchar(4000) NOT NULL,
	`operation` varchar(20) NOT NULL,
	`resource` varchar(4000) NOT NULL,
	`data` varchar(1000) DEFAULT NULL,
	`result` varchar(200) NOT NULL,
    ```
