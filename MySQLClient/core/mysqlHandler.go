package core

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ConnectMySQL function
func (mc *MySQLClient) ConnectMySQL() (db *sql.DB) {
	info := mc.dbUser + ":" + mc.dbPasswd + "@tcp(" + mc.dbHost + ")/" + mc.dbName

	db, err := sql.Open("mysql", info)
	for err != nil {
		fmt.Printf("Failed to connect to the MySQL server (%s, %s)\n", info, err.Error())
		time.Sleep(time.Second * 1)
	}
	db.SetMaxIdleConns(0)

	return db
}

// CreateTablesIfNotExist function
func (mc *MySQLClient) CreateTablesIfNotExist() bool {
	db := mc.ConnectMySQL()
	defer db.Close()

	if mc.dbMsgTable != "" {
		query := "CREATE TABLE IF NOT EXISTS `" + mc.dbMsgTable + "` (" +
			"    `id` int NOT NULL AUTO_INCREMENT," +
			"    `timestamp` int NOT NULL," +
			"    `updatedTime` varchar(30) NOT NULL," +
			"    `clusterName` varchar(100) NOT NULL," +
			"    `hostName` varchar(100) NOT NULL," +
			"    `hostIP` varchar(100) NOT NULL," +
			"    `level` varchar(20) NOT NULL," +
			"    `message` varchar(1000) NOT NULL," +
			"    PRIMARY KEY (`id`)" +
			");"

		if _, err := db.Query(query); err != nil {
			fmt.Printf("Failed to create %s (%s)\n", mc.dbMsgTable, err.Error())
			return false
		}
	}

	if mc.dbAlertTable != "" {
		query := "CREATE TABLE IF NOT EXISTS `" + mc.dbAlertTable + "` (" +
			"    `id` int NOT NULL AUTO_INCREMENT," +
			"    `timestamp` int NOT NULL," +
			"    `updatedTime` varchar(30) NOT NULL," +
			"    `clusterName` varchar(100) NOT NULL," +
			"    `hostName` varchar(100) NOT NULL," +
			"    `namespaceName` varchar(100) NOT NULL," +
			"    `podName` varchar(200) NOT NULL," +
			"    `containerID` varchar(200) NOT NULL," +
			"    `containerName` varchar(200) NOT NULL," +
			"    `hostPid` int NOT NULL," +
			"    `ppid` int NOT NULL," +
			"    `pid` int NOT NULL," +
			"    `uid` int NOT NULL," +
			"    `policyName` varchar(1000) NOT NULL," +
			"    `severity` varchar(100) NOT NULL," +
			"    `tags` varchar(1000) NOT NULL," +
			"    `message` varchar(1000) NOT NULL," +
			"    `type` varchar(20) NOT NULL," +
			"    `source` varchar(4000) NOT NULL," +
			"    `operation` varchar(20) NOT NULL," +
			"    `resource` varchar(4000) NOT NULL," +
			"    `data` varchar(1000) DEFAULT NULL," +
			"    `action` varchar(20) NOT NULL," +
			"    `result` varchar(200) NOT NULL," +
			"    PRIMARY KEY (`id`)" +
			");"

		if _, err := db.Query(query); err != nil {
			fmt.Printf("Failed to create %s (%s)\n", mc.dbAlertTable, err.Error())
			return false
		}
	}

	if mc.dbLogTable != "" {
		query := "CREATE TABLE IF NOT EXISTS `" + mc.dbLogTable + "` (" +
			"    `id` int NOT NULL AUTO_INCREMENT," +
			"    `timestamp` int NOT NULL," +
			"    `updatedTime` varchar(30) NOT NULL," +
			"    `clusterName` varchar(100) NOT NULL," +
			"    `hostName` varchar(100) NOT NULL," +
			"    `namespaceName` varchar(100) NOT NULL," +
			"    `podName` varchar(200) NOT NULL," +
			"    `containerID` varchar(200) NOT NULL," +
			"    `containerName` varchar(200) NOT NULL," +
			"    `hostPid` int NOT NULL," +
			"    `ppid` int NOT NULL," +
			"    `pid` int NOT NULL," +
			"    `uid` int NOT NULL," +
			"    `type` varchar(20) NOT NULL," +
			"    `source` varchar(4000) NOT NULL," +
			"    `operation` varchar(20) NOT NULL," +
			"    `resource` varchar(4000) NOT NULL," +
			"    `data` varchar(1000) DEFAULT NULL," +
			"    `result` varchar(200) NOT NULL," +
			"    PRIMARY KEY (`id`)" +
			");"

		if _, err := db.Query(query); err != nil {
			fmt.Printf("Failed to create %s (%s)\n", mc.dbLogTable, err.Error())
			return false
		}
	}

	return true
}
