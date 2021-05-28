package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"

	ll "github.com/accuknox/KubeArmor/KafkaClient/common"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"google.golang.org/grpc"

	"gopkg.in/confluentinc/confluent-kafka-go.v1/kafka"
)

// =============== //
// == Log Feeds == //
// =============== //

// KafkaClient Structure
type KafkaClient struct {
	// flag
	Running bool

	// server
	server string

	// kafka info
	bootstrapServer string

	// topic
	topicMsg   string
	topicAlert string
	topicLog   string

	// connection
	conn *grpc.ClientConn

	// client
	client pb.LogServiceClient

	// messages
	msgStream pb.LogService_WatchMessagesClient

	// alerts
	alertStream pb.LogService_WatchAlertsClient

	// logs
	logStream pb.LogService_WatchLogsClient

	// wait group
	WgClient sync.WaitGroup
}

// NewClient Function
func NewClient(server, bootstrapServer, topicMsg, topicAlert, topicLog string) *KafkaClient {
	kc := &KafkaClient{}

	kc.Running = true

	kc.server = server

	kc.bootstrapServer = bootstrapServer

	kc.topicMsg = topicMsg
	kc.topicAlert = topicAlert
	kc.topicLog = topicLog

	if kc.server != "" {
		conn, err := grpc.Dial(kc.server, grpc.WithInsecure())
		if err != nil {
			// fmt.Printf("Failed to connect to a gRPC server (%s)\n", err.Error())
			return nil
		}
		kc.conn = conn

		kc.client = pb.NewLogServiceClient(kc.conn)

		if topicMsg != "" {
			msgIn := pb.RequestMessage{}
			msgIn.Filter = ""

			msgStream, err := kc.client.WatchMessages(context.Background(), &msgIn)
			if err != nil {
				// fmt.Printf("Failed to call WatchMessages() (%s)\n", err.Error())
				return nil
			}
			kc.msgStream = msgStream
		}

		if topicAlert != "" {
			alertIn := pb.RequestMessage{}
			alertIn.Filter = ""

			alertStream, err := kc.client.WatchAlerts(context.Background(), &alertIn)
			if err != nil {
				// fmt.Printf("Failed to call WatchAlerts() (%s)\n", err.Error())
				return nil
			}
			kc.alertStream = alertStream
		}

		if topicLog != "" {
			logIn := pb.RequestMessage{}
			logIn.Filter = ""

			logStream, err := kc.client.WatchLogs(context.Background(), &logIn)
			if err != nil {
				// fmt.Printf("Failed to call WatchLogs() (%s)\n", err.Error())
				return nil
			}
			kc.logStream = logStream
		}
	}

	kc.WgClient = sync.WaitGroup{}

	return kc
}

// DoHealthCheck Function
func (kc *KafkaClient) DoHealthCheck() bool {
	// generate a nonce
	randNum := rand.Int31()

	// send a nonce
	nonce := pb.NonceMessage{Nonce: randNum}
	res, err := kc.client.HealthCheck(context.Background(), &nonce)
	if err != nil {
		fmt.Printf("Failed to call HealthCheck() (%s)\n", err.Error())
		return false
	}

	// check nonce
	if randNum != res.Retval {
		return false
	}

	return true
}

// WatchMessages Function
func (kc *KafkaClient) WatchMessages(msgPath string) error {
	kc.WgClient.Add(1)
	defer kc.WgClient.Done()

	producer, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": kc.bootstrapServer})
	if err != nil {
		fmt.Printf("Failed to create a new producer (%s)\n", err.Error())
		return err
	}
	defer producer.Close()

	for kc.Running {
		res, err := kc.msgStream.Recv()
		if err != nil {
			fmt.Printf("Failed to receive a message (%s)\n", err.Error())
			break
		}

		arr, _ := json.Marshal(res)
		str := fmt.Sprintf("%s", string(arr))

		go func() {
			for e := range producer.Events() {
				switch ev := e.(type) {
				case *kafka.Message:
					if ev.TopicPartition.Error != nil {
						fmt.Printf("Delivery failed: %v\n", ev.TopicPartition)
					}
				}
			}
		}()

		producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{Topic: &kc.topicMsg, Partition: kafka.PartitionAny},
			Value:          []byte(str),
		}, nil)

		if msgPath == "stdout" {
			fmt.Println(str)
		} else if msgPath != "none" {
			ll.StrToFile(str+"\n", msgPath)
		}
	}

	return nil
}

// ConsumeMessages Function
func (kc *KafkaClient) ConsumeMessages() error {
	kc.WgClient.Add(1)
	defer kc.WgClient.Done()

	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers": kc.bootstrapServer,
		"group.id":          "kafka-group",
		"auto.offset.reset": "earliest",
	})
	if err != nil {
		fmt.Printf("Failed to create a new consumer (%s)\n", err.Error())
		return err
	}
	defer consumer.Close()

	consumer.SubscribeTopics([]string{kc.topicMsg}, nil)

	for kc.Running {
		ev := consumer.Poll(100)
		if ev == nil {
			continue
		}

		switch e := ev.(type) {
		case *kafka.Message:
			fmt.Printf("%s: %s\n", e.TopicPartition, string(e.Value))
		case kafka.Error:
			fmt.Printf("Failed to consume a message (%v, %v)\n", e.Code(), e)
		}
	}

	return nil
}

// WatchAlerts Function
func (kc *KafkaClient) WatchAlerts(logPath string) error {
	kc.WgClient.Add(1)
	defer kc.WgClient.Done()

	producer, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": kc.bootstrapServer})
	if err != nil {
		fmt.Printf("Failed to create a new producer (%s)\n", err.Error())
		return err
	}
	defer producer.Close()

	for kc.Running {
		res, err := kc.alertStream.Recv()
		if err != nil {
			fmt.Printf("Failed to receive an alert (%s)\n", err.Error())
			break
		}

		arr, _ := json.Marshal(res)
		str := fmt.Sprintf("%s", string(arr))

		go func() {
			for e := range producer.Events() {
				switch ev := e.(type) {
				case *kafka.Message:
					if ev.TopicPartition.Error != nil {
						fmt.Printf("Delivery failed: %v\n", ev.TopicPartition)
					}
				}
			}
		}()

		producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{Topic: &kc.topicAlert, Partition: kafka.PartitionAny},
			Value:          []byte(str),
		}, nil)

		if logPath == "stdout" {
			fmt.Println(str)
		} else if logPath != "none" {
			ll.StrToFile(str+"\n", logPath)
		}
	}

	return nil
}

// ConsumeAlerts Function
func (kc *KafkaClient) ConsumeAlerts() error {
	kc.WgClient.Add(1)
	defer kc.WgClient.Done()

	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers": kc.bootstrapServer,
		"group.id":          "kafka-group",
		"auto.offset.reset": "earliest",
	})
	if err != nil {
		fmt.Printf("Failed to create a new consumer (%s)\n", err.Error())
		return err
	}
	defer consumer.Close()

	consumer.SubscribeTopics([]string{kc.topicAlert}, nil)

	for kc.Running {
		ev := consumer.Poll(100)
		if ev == nil {
			continue
		}

		switch e := ev.(type) {
		case *kafka.Message:
			fmt.Printf("%s: %s\n", e.TopicPartition, string(e.Value))
		case kafka.Error:
			fmt.Printf("Failed to consume an alert (%v, %v)\n", e.Code(), e)
		}
	}

	return nil
}

// WatchLogs Function
func (kc *KafkaClient) WatchLogs(logPath string) error {
	kc.WgClient.Add(1)
	defer kc.WgClient.Done()

	producer, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": kc.bootstrapServer})
	if err != nil {
		fmt.Printf("Failed to create a new producer (%s)\n", err.Error())
		return err
	}
	defer producer.Close()

	for kc.Running {
		res, err := kc.logStream.Recv()
		if err != nil {
			fmt.Printf("Failed to receive a log (%s)\n", err.Error())
			break
		}

		arr, _ := json.Marshal(res)
		str := fmt.Sprintf("%s", string(arr))

		go func() {
			for e := range producer.Events() {
				switch ev := e.(type) {
				case *kafka.Message:
					if ev.TopicPartition.Error != nil {
						fmt.Printf("Delivery failed: %v\n", ev.TopicPartition)
					}
				}
			}
		}()

		producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{Topic: &kc.topicLog, Partition: kafka.PartitionAny},
			Value:          []byte(str),
		}, nil)

		if logPath == "stdout" {
			fmt.Println(str)
		} else if logPath != "none" {
			ll.StrToFile(str+"\n", logPath)
		}
	}

	return nil
}

// ConsumeLogs Function
func (kc *KafkaClient) ConsumeLogs() error {
	kc.WgClient.Add(1)
	defer kc.WgClient.Done()

	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers": kc.bootstrapServer,
		"group.id":          "kafka-group",
		"auto.offset.reset": "earliest",
	})
	if err != nil {
		fmt.Printf("Failed to create a new consumer (%s)\n", err.Error())
		return err
	}
	defer consumer.Close()

	consumer.SubscribeTopics([]string{kc.topicLog}, nil)

	for kc.Running {
		ev := consumer.Poll(100)
		if ev == nil {
			continue
		}

		switch e := ev.(type) {
		case *kafka.Message:
			fmt.Printf("%s: %s\n", e.TopicPartition, string(e.Value))
		case kafka.Error:
			fmt.Printf("Failed to consume a log (%v, %v)\n", e.Code(), e)
		}
	}

	return nil
}

// DestroyClient Function
func (kc *KafkaClient) DestroyClient() error {
	if kc.server != "" {
		if err := kc.conn.Close(); err != nil {
			return err
		}
	}

	kc.WgClient.Wait()

	return nil
}
