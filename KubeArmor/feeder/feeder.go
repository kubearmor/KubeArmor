package feeder

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"

	pb "github.com/accuknox/KubeArmor/KubeArmor/feeder/protobuf"
	"google.golang.org/grpc"
)

// Feeder Structure
type Feeder struct {
	// server
	server string

	// connection
	conn *grpc.ClientConn

	// client
	client pb.LogMessageClient

	// audit log stream
	auditLogStream pb.LogMessage_AuditLogsClient

	// system log stream
	systemLogStream pb.LogMessage_SystemLogsClient
}

// NewFeeder Function
func NewFeeder(server, logType string) *Feeder {
	fd := &Feeder{}

	fd.server = server

	for {
		if ok, _ := fd.DoHealthCheck(); ok {
			break
		}

		kg.Print("Waiting until the operator is ready")

		time.Sleep(time.Second * 1)
	}

	conn, err := grpc.Dial(fd.server, grpc.WithInsecure())
	if err != nil {
		kg.Err(err.Error())
		return nil
	}

	fd.conn = conn

	if logType == "AuditLog" {
		fd.client = pb.NewLogMessageClient(fd.conn)

		stream, err := fd.client.AuditLogs(context.Background())
		if err != nil {
			kg.Err(err.Error())
			return nil
		}

		fd.auditLogStream = stream
	} else if logType == "SystemLog" {
		fd.client = pb.NewLogMessageClient(fd.conn)

		stream, err := fd.client.SystemLogs(context.Background())
		if err != nil {
			kg.Err(err.Error())
			return nil
		}

		fd.systemLogStream = stream
	} else {
		kg.Printf("Not supported type (%s)", logType)
		fd.conn.Close()
		return nil
	}

	return fd
}

// DestroyFeeder Function
func (fd *Feeder) DestroyFeeder() {
	fd.conn.Close()
}

// SendAuditLog Function
func (fd *Feeder) SendAuditLog(auditLog tp.AuditLog) {
	log := pb.AuditLog{}
	fd.auditLogStream.Send(&log)

	_, err := fd.auditLogStream.CloseAndRecv()
	if err != nil {
		kg.Err(err.Error())
		return
	}
}

// SendSystemLog Function
func (fd *Feeder) SendSystemLog(systemLog tp.SystemLog) {
	log := pb.SystemLog{}
	fd.systemLogStream.Send(&log)

	_, err := fd.systemLogStream.CloseAndRecv()
	if err != nil {
		kg.Err(err.Error())
		return
	}
}

// DoHealthCheck Function
func (fd *Feeder) DoHealthCheck() (bool, string) {
	// connect to server
	conn, err := grpc.Dial(fd.server, grpc.WithInsecure())
	if err != nil {
		kg.Err(err.Error())
		return false, fmt.Sprintf("Failed to connect the server (%s)", fd.server)
	}
	defer conn.Close()

	// set client
	client := pb.NewLogMessageClient(conn)

	// generate nonce
	rand := rand.Int31()

	// send a nonce
	nonce := pb.NonceMessage{Nonce: rand}
	res, err := client.HealthCheck(context.Background(), &nonce)
	if err != nil {
		return false, err.Error()
	}

	// check nonces
	if rand != res.Retval {
		return false, "Nonces are different"
	}

	return true, "success"
}
