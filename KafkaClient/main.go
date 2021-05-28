package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/accuknox/KubeArmor/KafkaClient/core"
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

	gRPCPtr := flag.String("gRPC", "", "gRPC server information")
	msgPathPtr := flag.String("msgPath", "none", "Output location for messages, {path|stdout|none}")
	logPathPtr := flag.String("logPath", "none", "Output location for alerts and logs, {path|stdout|none}")
	consumerPtr := flag.String("consumer", "", "Topic to consume")
	flag.Parse()

	// == //

	gRPC := ""

	fmt.Println("== KubeArmor information ==")

	if *gRPCPtr != "" {
		gRPC = *gRPCPtr
	} else {
		if val, ok := os.LookupEnv("KUBEARMOR_SERVICE"); ok {
			gRPC = val
		} else {
			gRPC = "localhost:32767"
		}
	}

	fmt.Println("  gRPC server: " + gRPC)

	// == //

	fmt.Println("== Kafka information ==")

	bootstrapServer := ""

	if val, ok := os.LookupEnv("KAFKA_BOOTSTRAP_SERVER"); ok {
		bootstrapServer = val
		fmt.Println("  KAFKA_BOOTSTRAP_SERVER: " + bootstrapServer)
	} else {
		fmt.Println("Failed to get KAFKA_BOOTSTRAP_SERVER from env")
		return
	}

	topicMsg := ""
	topicAlert := ""
	topicLog := ""

	if val, ok := os.LookupEnv("TOPIC_MSG"); ok {
		topicMsg = val
		fmt.Println("  TOPIC_MSG:              " + topicMsg)
	}

	if val, ok := os.LookupEnv("TOPIC_ALERT"); ok {
		topicAlert = val
		fmt.Println("  TOPIC_ALERT:            " + topicAlert)
	}

	if val, ok := os.LookupEnv("TOPIC_LOG"); ok {
		topicLog = val
		fmt.Println("  TOPIC_LOG:              " + topicLog)
	}

	if topicMsg == "" && topicAlert == "" && topicLog == "" {
		fmt.Println("Failed to get some of TOPIC_MSG, TOPIC_ALERT, and TOPIC_LOG")
		return
	} else if *consumerPtr != "" && *consumerPtr != topicMsg && *consumerPtr != topicAlert && *consumerPtr != topicLog {
		fmt.Printf("Failed to find %s among TOPIC_MSG, TOPIC_ALERT, and TOPIC_LOG\n", *consumerPtr)
		return
	}

	// == //

	if *consumerPtr != "" { // consumer
		// create a client
		logClient := core.NewClient("", bootstrapServer, topicMsg, topicAlert, topicLog)
		if logClient == nil {
			fmt.Printf("Failed to create a Kafka client (%s)\n", bootstrapServer)
			return
		}
		fmt.Printf("Created a Kafka client (%s)\n", bootstrapServer)

		if *consumerPtr == topicMsg {
			go logClient.ConsumeMessages()
			fmt.Println("Started to consume messages")
		}

		if *consumerPtr == topicAlert {
			go logClient.ConsumeAlerts()
			fmt.Println("Started to consume alerts")
		}

		if *consumerPtr == topicLog {
			go logClient.ConsumeLogs()
			fmt.Println("Started to consume logs")
		}

		// listen for interrupt signals
		sigChan := GetOSSigChannel()
		<-sigChan
		close(StopChan)

		logClient.Running = false
		time.Sleep(time.Second * 1)

		// destroy the client
		if err := logClient.DestroyClient(); err != nil {
			fmt.Printf("Failed to destroy the Kafka client (%s)\n", err.Error())
			return
		}
		fmt.Println("Destroyed the Kafka client")
	} else { // producer
		// create a client
		logClient := core.NewClient(gRPC, bootstrapServer, topicMsg, topicAlert, topicLog)
		if logClient == nil {
			fmt.Printf("Failed to create a gRPC client (%s)\n", gRPC)
			return
		}
		fmt.Printf("Created a gRPC client (%s)\n", gRPC)

		// do healthcheck
		if ok := logClient.DoHealthCheck(); !ok {
			fmt.Println("Failed to check the liveness of the gRPC server")
			return
		}
		fmt.Println("Checked the liveness of the gRPC server")

		if topicMsg != "" {
			go logClient.WatchMessages(*msgPathPtr)
			fmt.Println("Started to watch messages")
		}

		if topicAlert != "" {
			go logClient.WatchAlerts(*logPathPtr)
			fmt.Println("Started to watch alerts")
		}

		if topicLog != "" {
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
			fmt.Printf("Failed to destroy the gRPC client (%s)\n", err.Error())
			return
		}
		fmt.Println("Destroyed the gRPC client")
	}

	// == //
}
