// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package log

import (
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
	config := zap.NewProductionConfig()
	config.EncoderConfig.EncodeTime = customTimeEncoder

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

// Warn Function
func Warn(message string) {
	zapLogger.Warn(message)
}

// Warnf Function
func Warnf(message string, args ...interface{}) {
	zapLogger.Warnf(message, args...)
}
