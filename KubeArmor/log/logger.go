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
	enc.AppendString(t.Format("2020-01-01 00:00:00.000000"))
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

	defer logger.Sync()
	zapLogger = logger.Sugar()
}

// ======================= //
// == Logging Functions == //
// ======================= //

// Print Function
func Print(message string) {
	zapLogger.Info(message)
	zapLogger.Sync()
}

// PrintfNotInsert Function
func PrintfNotInsert(message string, args ...interface{}) {
	zapLogger.Infof(message, args...)
	zapLogger.Sync()
}

// Printf Function
func Printf(message string, args ...interface{}) {
	zapLogger.Infof(message, args...)
	zapLogger.Sync()
}

// Debug Function
func Debug(message string) {
	zapLogger.Debug(message)
	zapLogger.Sync()
}

// Debugf Function
func Debugf(message string, args ...interface{}) {
	zapLogger.Debugf(message, args...)
	zapLogger.Sync()
}

// Err Function
func Err(message string) {
	zapLogger.Error(message)
	zapLogger.Sync()
}

// Errf Function
func Errf(message string, args ...interface{}) {
	zapLogger.Errorf(message, args...)
	zapLogger.Sync()
}
