// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package log

import (
	"encoding/json"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ============ //
// == Logger == //
// ============ //

// zapLogger Handler
var zapLogger *zap.SugaredLogger

// init Function
func init() {
	initLogger()
}

// customTimeEncoder Function
func customTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05.000000"))
}

// initLogger Function
func initLogger() {
	defaultConfig := []byte(`{
		"level": "debug",
		"encoding": "console",
		"outputPaths": ["stdout"],
		"encoderConfig": {
			"messageKey": "message",
			"levelKey": "level",
			"nameKey": "logger",
			"timeKey": "time",
			"callerKey": "logger",
			"stacktraceKey": "stacktrace",
			"callstackKey": "callstack",
			"errorKey": "error",
			"levelEncoder": "capitalColor",
			"durationEncoder": "second",
			"sampling": {
				"initial": "3",
				"thereafter": "10"
			}
		}
	}`)

	config := zap.Config{}
	if err := json.Unmarshal(defaultConfig, &config); err != nil {
		panic(err)
	}

	config.EncoderConfig.EncodeTime = customTimeEncoder
	config.Level.SetLevel(zap.DebugLevel) // if we need to set log level

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}

	zapLogger = logger.Sugar()
}

// ======================= //
// == Logging Functions == //
// ======================= //

// Print Function
func Print(message string) {
	zapLogger.Info(message)
}

// Printf Function
func Printf(message string, args ...interface{}) {
	zapLogger.Infof(message, args...)
}

// Debug Function
func Debug(message string) {
	zapLogger.Debug(message)
}

// Debugf Function
func Debugf(message string, args ...interface{}) {
	zapLogger.Debugf(message, args...)
}

// Err Function
func Err(message string) {
	zapLogger.Error(message)
}

// Errf Function
func Errf(message string, args ...interface{}) {
	zapLogger.Errorf(message, args...)
}
