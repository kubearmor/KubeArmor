// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package feeder

import (
	"context"
	"fmt"
	"strings"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// OTelExporter handles exporting KubeArmor events to an OpenTelemetry collector
type OTelExporter struct {
	loggerProvider *sdklog.LoggerProvider
	logger         log.Logger
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewOTelExporter initializes a new OpenTelemetry log exporter
func NewOTelExporter(endpoint string, insecure bool) (*OTelExporter, error) {
	ctx, cancel := context.WithCancel(context.Background())

	var opts []otlploggrpc.Option
	if endpoint != "" {
		opts = append(opts, otlploggrpc.WithEndpoint(endpoint))
	}
	if insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	}

	exporter, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create OTel log exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("kubearmor"),
		),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create OTel resource: %w", err)
	}

	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	logger := lp.Logger("kubearmor-feeder")

	return &OTelExporter{
		loggerProvider: lp,
		logger:         logger,
		ctx:            ctx,
		cancel:         cancel,
	}, nil
}

// Shutdown closes the OTel logger provider and flushes remaining logs
func (o *OTelExporter) Shutdown() {
	o.cancel()
	if o.loggerProvider != nil {
		if err := o.loggerProvider.Shutdown(context.Background()); err != nil {
			kg.Errf("Failed to shutdown OTel logger provider: %v", err)
		}
	}
}

// PushLog forwards KubeArmor security alerts and telemetry logs to the OTel collector
func (o *OTelExporter) PushLog(logData tp.Log) {
	severity := mapSeverity(logData.Severity)

	bodyStr := logData.Message
	if bodyStr == "" {
		bodyStr = fmt.Sprintf("%s event on %s by %s", logData.Type, logData.Operation, logData.ProcessName)
	}

	attrs := []log.KeyValue{
		// OTel semantic conventions for Kubernetes & Containers
		log.String(string(semconv.K8SClusterNameKey), logData.ClusterName),
		log.String(string(semconv.K8SNamespaceNameKey), logData.NamespaceName),
		log.String(string(semconv.K8SPodNameKey), logData.PodName),
		log.String(string(semconv.ContainerNameKey), logData.ContainerName),
		log.String(string(semconv.ContainerIDKey), logData.ContainerID),
		log.String(string(semconv.ContainerImageNameKey), logData.ContainerImage),

		// Host & Node
		log.String(string(semconv.HostNameKey), logData.HostName),
		log.String(string(semconv.HostIDKey), logData.NodeID),

		// Process
		log.Int(string(semconv.ProcessPIDKey), int(logData.PID)),
		log.Int("process.parent.pid", int(logData.PPID)),
		log.String(string(semconv.ProcessExecutableNameKey), logData.ProcessName),
		log.String("process.parent.executable.name", logData.ParentProcessName),

		// User
		log.String("user.name", logData.UserName),
		log.Int("user.id", int(logData.UID)),

		// KubeArmor custom attributes
		log.String("kubearmor.enforcer", logData.Enforcer),
		log.String("kubearmor.policy_name", logData.PolicyName),
		log.String("kubearmor.type", logData.Type),
		log.String("kubearmor.source", logData.Source),
		log.String("kubearmor.operation", logData.Operation),
		log.String("kubearmor.resource", logData.Resource),
		log.String("kubearmor.cwd", logData.Cwd),
		log.String("kubearmor.tty", logData.TTY),
		log.String("kubearmor.data", logData.Data),
		log.String("kubearmor.action", logData.Action),
		log.String("kubearmor.result", logData.Result),
		log.String("kubearmor.severity", logData.Severity),
		log.String("kubearmor.tags", logData.Tags),
	}

	// Add event data map as attributes
	for k, v := range logData.EventData {
		attrs = append(attrs, log.String("kubearmor.event_data."+strings.ToLower(k), v))
	}

	// Set timestamp
	var logTime time.Time
	if logData.Timestamp > 0 {
		logTime = time.Unix(0, logData.Timestamp)
	} else {
		logTime = time.Now()
	}

	var record log.Record
	record.SetTimestamp(logTime)
	record.SetSeverity(severity)
	record.SetBody(log.StringValue(bodyStr))
	record.AddAttributes(attrs...)

	o.logger.Emit(o.ctx, record)
}

// PushMessage forwards KubeArmor system/internal messages to the OTel collector
func (o *OTelExporter) PushMessage(level, message string) {
	severity := mapMessageLevel(level)

	var record log.Record
	record.SetTimestamp(time.Now())
	record.SetSeverity(severity)
	record.SetBody(log.StringValue(message))
	record.AddAttributes(
		log.String("kubearmor.type", "Message"),
		log.String("kubearmor.level", level),
	)

	o.logger.Emit(o.ctx, record)
}

// mapSeverity maps KubeArmor's severity string into OTel's standard severity levels
func mapSeverity(severityStr string) log.Severity {
	switch strings.ToLower(severityStr) {
	case "critical", "10", "9":
		return log.SeverityFatal
	case "high", "8", "7", "6":
		return log.SeverityError
	case "medium", "5", "4", "3":
		return log.SeverityWarn
	case "low", "2", "1":
		return log.SeverityInfo
	default:
		return log.SeverityInfo
	}
}

// mapMessageLevel maps internal log levels (DEBUG/INFO/WARN/ERROR) to OTel severity
func mapMessageLevel(level string) log.Severity {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return log.SeverityDebug
	case "INFO":
		return log.SeverityInfo
	case "WARN", "WARNING":
		return log.SeverityWarn
	case "ERROR":
		return log.SeverityError
	default:
		return log.SeverityInfo
	}
}
