// filepath: KubeArmor/KubeArmor/log/logger_test.go
package log

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func resetLogger() {
	zapLogger = nil
}

func TestInitLogger_Default(t *testing.T) {
	resetLogger()
	os.Unsetenv("DEBUG")

	initLogger()
	assert.NotNil(t, zapLogger, "zapLogger should be initialized")
}

func TestInitLogger_WithDebugTrue(t *testing.T) {
	resetLogger()
	os.Setenv("DEBUG", "true")
	defer os.Unsetenv("DEBUG")

	initLogger()
	assert.NotNil(t, zapLogger, "zapLogger should be initialized")

	// Verify debug level is enabled
	assert.True(t, zapLogger.Desugar().Core().Enabled(zap.DebugLevel))
}

func TestInitLogger_WithDebugFalse(t *testing.T) {
	resetLogger()
	os.Setenv("DEBUG", "false")
	defer os.Unsetenv("DEBUG")

	initLogger()
	assert.NotNil(t, zapLogger, "zapLogger should be initialized")

	// Verify debug level is not enabled
	assert.False(t, zapLogger.Desugar().Core().Enabled(zap.DebugLevel))
}

func TestCustomTimeEncoder(t *testing.T) {
	testTime := time.Date(2023, 12, 25, 12, 0, 0, 0, time.UTC)
	enc := &testArrayEncoder{}
	customTimeEncoder(testTime, enc)

	expectedFormat := "2023-12-25 12:00:00.000000"
	assert.Equal(t, []interface{}{expectedFormat}, enc.elements, "Time format should match expected")
}

// testArrayEncoder is a minimal implementation of zapcore.ArrayEncoder for testing.
type testArrayEncoder struct {
	elements []interface{}
}

func (e *testArrayEncoder) AppendBool(val bool)                 { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendByteString(val []byte)          { e.elements = append(e.elements, string(val)) }
func (e *testArrayEncoder) AppendComplex128(val complex128)      { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendComplex64(val complex64)        { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendFloat64(val float64)            { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendFloat32(val float32)            { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendInt(val int)                    { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendInt64(val int64)                { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendInt32(val int32)                { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendInt16(val int16)                { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendInt8(val int8)                  { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendString(val string)              { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendUint(val uint)                  { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendUint64(val uint64)              { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendUint32(val uint32)              { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendUint16(val uint16)              { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendUint8(val uint8)                { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendUintptr(val uintptr)            { e.elements = append(e.elements, val) }
func (e *testArrayEncoder) AppendReflected(val interface{}) error { e.elements = append(e.elements, val); return nil }
func (e *testArrayEncoder) AppendArray(arr zapcore.ArrayMarshaler) error { return nil }
func (e *testArrayEncoder) AppendObject(obj zapcore.ObjectMarshaler) error { return nil }

func TestLoggingFunctions(t *testing.T) {
	resetLogger()
	initLogger()

	// Test each logging function doesn't panic
	assert.NotPanics(t, func() { Print("test message") })
	assert.NotPanics(t, func() { Printf("test %s", "message") })
	assert.NotPanics(t, func() { Debug("test message") })
	assert.NotPanics(t, func() { Debugf("test %s", "message") })
	assert.NotPanics(t, func() { Err("test message") })
	assert.NotPanics(t, func() { Errf("test %s", "message") })
	assert.NotPanics(t, func() { Warn("test message") })
	assert.NotPanics(t, func() { Warnf("test %s", "message") })
}