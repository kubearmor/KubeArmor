package feeder

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"

	pb "github.com/accuknox/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// Feeder Structure
type Feeder struct {
	// server
	server string

	// log type
	logType string

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

	if strings.HasPrefix(server, "kubearmor-logserver") {
		server = strings.Replace(server, "kubearmor-logserver", os.Getenv("KUBEARMOR_LOGSERVER_SERVICE_HOST"), -1)
	}

	fd.server = server
	fd.logType = logType

	for {
		if _, ok := fd.DoHealthCheck(); ok {
			break
		}
		time.Sleep(time.Second * 1)
	}

	conn, err := grpc.Dial(fd.server, grpc.WithInsecure())
	if err != nil {
		kg.Err(err.Error())
		return nil
	}
	fd.conn = conn

	fd.client = pb.NewLogMessageClient(fd.conn)

	if logType == "AuditLog" {
		auditLogStream, err := fd.client.AuditLogs(context.Background())
		if err != nil {
			kg.Err(err.Error())
			return nil
		}
		fd.auditLogStream = auditLogStream
	} else if logType == "SystemLog" {
		systemLogStream, err := fd.client.SystemLogs(context.Background())
		if err != nil {
			kg.Err(err.Error())
			return nil
		}
		fd.systemLogStream = systemLogStream
	}

	return fd
}

// DestroyFeeder Function
func (fd *Feeder) DestroyFeeder() error {
	if err := fd.conn.Close(); err != nil {
		return err
	}

	return nil
}

// DoHealthCheck Function
func (fd *Feeder) DoHealthCheck() (string, bool) {
	// connect to server
	conn, err := grpc.Dial(fd.server, grpc.WithInsecure())
	if err != nil {
		kg.Err(err.Error())
		return fmt.Sprintf("Failed to connect the server (%s)", fd.server), false
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
		return err.Error(), false
	}

	// check nonces
	if rand != res.Retval {
		return "Nonces are different", false
	}

	return "success", true
}

// SendAuditLog Function
func (fd *Feeder) SendAuditLog(auditLog tp.AuditLog) error {
	if fd.logType != "AuditLog" {
		return nil
	}

	log := pb.AuditLog{}

	log.UpdatedTime = auditLog.UpdatedTime

	log.HostName = auditLog.HostName

	log.NamespaceName = auditLog.NamespaceName
	log.PodName = auditLog.PodName

	log.ContainerID = auditLog.ContainerID
	log.ContainerName = auditLog.ContainerName

	log.HostPID = auditLog.HostPID
	log.Source = auditLog.Source
	log.Operation = auditLog.Operation
	log.Resource = auditLog.Resource
	log.Result = auditLog.Result

	log.RawData = auditLog.RawData

	if err := fd.auditLogStream.Send(&log); err != nil {
		kg.Errf("Failed to send an audit log, trying to reconnect to the gRPC server (%s)", err.Error())

		if err := fd.conn.Close(); err != nil {
			kg.Errf("Failed to close the gRPC server (%s)", err.Error())
			return err
		}

		conn, err := grpc.Dial(fd.server, grpc.WithInsecure())
		if err != nil {
			kg.Errf("Failed to reconnect to the gRPC server (%s)", err.Error())
			return err
		}
		fd.conn = conn

		fd.client = pb.NewLogMessageClient(fd.conn)

		auditLogStream, err := fd.client.AuditLogs(context.Background())
		if err != nil {
			kg.Errf("Failed to reconnect to the gRPC server (%s)", err.Error())
			return err
		}
		fd.auditLogStream = auditLogStream

		kg.Print("Reconnected the gRPC server for audit logs")

		if err := fd.auditLogStream.Send(&log); err != nil {
			kg.Errf("Failed to send the audit log again (%s)", err.Error())
			return err
		}
	}

	return nil
}

// SendSystemLog Function
func (fd *Feeder) SendSystemLog(systemLog tp.SystemLog) error {
	if fd.logType != "SystemLog" {
		return nil
	}

	log := pb.SystemLog{}

	log.UpdatedTime = systemLog.UpdatedTime

	log.HostName = systemLog.HostName

	log.NamespaceName = systemLog.NamespaceName
	log.PodName = systemLog.PodName

	log.ContainerID = systemLog.ContainerID
	log.ContainerName = systemLog.ContainerName

	log.HostPID = systemLog.HostPID
	log.PPID = systemLog.PPID
	log.PID = systemLog.PID
	log.UID = systemLog.UID

	log.Source = systemLog.Source
	log.Operation = systemLog.Operation
	log.Resource = systemLog.Resource
	log.Args = systemLog.Args
	log.Result = systemLog.Result

	if err := fd.systemLogStream.Send(&log); err != nil {
		kg.Errf("Failed to send a system log, trying to reconnect to the gRPC server (%s)", err.Error())

		if err := fd.conn.Close(); err != nil {
			kg.Errf("Failed to close the gRPC server (%s)", err.Error())
			return err
		}

		conn, err := grpc.Dial(fd.server, grpc.WithInsecure())
		if err != nil {
			kg.Errf("Failed to reconnect to the gRPC server (%s)", err.Error())
			return err
		}
		fd.conn = conn

		fd.client = pb.NewLogMessageClient(fd.conn)

		systemLogStream, err := fd.client.SystemLogs(context.Background())
		if err != nil {
			kg.Errf("Failed to reconnect to the gRPC server (%s)", err.Error())
			return err
		}
		fd.systemLogStream = systemLogStream

		kg.Print("Reconnected the gRPC server for system logs")

		if err := fd.systemLogStream.Send(&log); err != nil {
			kg.Errf("Failed to send the system log again (%s)", err.Error())
			return err
		}
	}

	return nil
}
