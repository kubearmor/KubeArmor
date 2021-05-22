package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/accuknox/KubeArmor/MySQLClient/core"

	_ "github.com/go-sql-driver/mysql"
)

// StopChan Channel
var StopChan chan struct{}

// init Function
func init() {
	StopChan = make(chan struct{})
}

// ==================== //
// == Signal Handler == //
// ==================== //

// GetOSSigChannel Function
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGKILL,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// ========== //
// == Main == //
// ========== //

func main() {
	// == //

	gRPCPtr := flag.String("gRPC", "localhost:32767", "gRPC server information")
	msgPathPtr := flag.String("msgPath", "none", "Output location for messages, {path|stdout|none}")
	logPathPtr := flag.String("logPath", "none", "Output location for alerts and logs, {path|stdout|none}")
	dropTablePtr := flag.Bool("dropTables", false, "Flag to drop the existing tables")
	flag.Parse()

	// == //

	dbHost := ""
	dbName := ""
	dbUser := ""
	dbPasswd := ""

	fmt.Println("== Database information ==")

	if val, ok := os.LookupEnv("DB_HOST"); ok {
		dbHost = val
		fmt.Println("  DB_HOST:     " + dbHost)
	} else if val, ok := os.LookupEnv("KUBEARMOR_MYSQL_PORT"); ok {
		dbHost = val[6:]
		fmt.Println("  DB_HOST:     " + dbHost)
	} else {
		fmt.Errorf("Failed to get DB_HOST from env")
		return
	}

	if val, ok := os.LookupEnv("DB_NAME"); ok {
		dbName = val
		fmt.Println("  DB_NAME:     " + dbName)
	} else {
		fmt.Errorf("Failed to get DB_NAME from env")
		return
	}

	if val, ok := os.LookupEnv("DB_USER"); ok {
		dbUser = val
		fmt.Println("  DB_USER:     " + dbUser)
	} else {
		fmt.Errorf("Failed to get DB_USER from env")
		return
	}

	if val, ok := os.LookupEnv("DB_PASSWD"); ok {
		dbPasswd = val
		fmt.Println("  DB_PASSWD:   ********")
	} else {
		fmt.Errorf("Failed to get DB_PASSWD from env")
		return
	}

	dbMsgTable := ""
	dbAlertTable := ""
	dbLogTable := ""

	if val, ok := os.LookupEnv("TABLE_MSG"); ok {
		dbMsgTable = val
		fmt.Println("  TABLE_MSG:   " + dbMsgTable)
	}

	if val, ok := os.LookupEnv("TABLE_ALERT"); ok {
		dbAlertTable = val
		fmt.Println("  TABLE_ALERT: " + dbAlertTable)
	}

	if val, ok := os.LookupEnv("TABLE_LOG"); ok {
		dbLogTable = val
		fmt.Println("  TABLE_LOG:   " + dbLogTable)
	}

	if dbMsgTable == "" && dbAlertTable == "" && dbLogTable == "" {
		fmt.Errorf("Failed to get some of TABLE_MSG, TABLE_ALERT, and TABLE_LOG")
		return
	}

	// == //

	db, err := sql.Open("mysql", dbUser+":"+dbPasswd+"@tcp("+dbHost+")/"+dbName)
	if err != nil {
		fmt.Errorf("Failed to connect to the MySQL database (%s)", err.Error())
		return
	}
	db.Close()

	// == //

	if *dropTablePtr {
		db, err := sql.Open("mysql", dbUser+":"+dbPasswd+"@tcp("+dbHost+")/"+dbName)
		if err != nil {
			fmt.Errorf("Failed to connect to the MySQL database (%s)", err.Error())
			return
		}

		if dbMsgTable != "" {
			query := "DROP TABLE IF EXISTS `" + dbMsgTable + "`;"

			if _, err := db.Query(query); err != nil {
				fmt.Errorf("Failed to drop %s (%s)", dbMsgTable, err.Error())
				return
			}

			fmt.Println("Dropped the table " + dbMsgTable)
		}

		if dbAlertTable != "" {
			query := "DROP TABLE IF EXISTS `" + dbAlertTable + "`;"

			if _, err := db.Query(query); err != nil {
				fmt.Errorf("Failed to drop %s (%s)", dbAlertTable, err.Error())
				return
			}

			fmt.Println("Dropped the table " + dbAlertTable)
		}

		if dbLogTable != "" {
			query := "DROP TABLE IF EXISTS `" + dbLogTable + "`;"

			if _, err := db.Query(query); err != nil {
				fmt.Errorf("Failed to drop %s (%s)", dbLogTable, err.Error())
				return
			}

			fmt.Println("Dropped the table " + dbLogTable)
		}

		db.Close()

		return
	}

	// == //

	// create a client
	logClient := core.NewClient(*gRPCPtr, dbHost, dbName, dbUser, dbPasswd, dbMsgTable, dbAlertTable, dbLogTable)
	if logClient == nil {
		fmt.Errorf("Failed to create a gRPC client (%s)", *gRPCPtr)
		return
	}
	fmt.Printf("Created a gRPC client (%s)\n", *gRPCPtr)

	// create DB tables
	if ok := logClient.CreateTablesIfNotExist(); !ok {
		// destroy the client
		if err := logClient.DestroyClient(); err != nil {
			fmt.Errorf("Failed to destroy the gRPC client (%s)", err.Error())
			return
		}
		fmt.Println("Destroyed the gRPC client")
		return
	}

	// do healthcheck
	if ok := logClient.DoHealthCheck(); !ok {
		fmt.Errorf("Failed to check the liveness of the gRPC server")
		return
	}
	fmt.Println("Checked the liveness of the gRPC server")

	if dbMsgTable != "" {
		go logClient.WatchMessages(*msgPathPtr)
		fmt.Println("Started to watch messages")
	}

	if dbAlertTable != "" {
		go logClient.WatchAlerts(*logPathPtr)
		fmt.Println("Started to watch alerts")
	}

	if dbLogTable != "" {
		go logClient.WatchLogs(*logPathPtr)
		fmt.Println("Started to watch logs")
	}

	// listen for interrupt signals
	sigChan := GetOSSigChannel()
	<-sigChan
	close(StopChan)

	logClient.Running = false
	time.Sleep(time.Second * 1)

	// destroy the client
	if err := logClient.DestroyClient(); err != nil {
		fmt.Errorf("Failed to destroy the gRPC client (%s)", err.Error())
		return
	}
	fmt.Println("Destroyed the gRPC client")

	// == //
}
