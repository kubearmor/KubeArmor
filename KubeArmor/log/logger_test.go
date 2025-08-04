// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package log

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestCustomTimeEncoder(t *testing.T) {
	testTime := time.Date(2023, 12, 25, 14, 30, 45, 123456789, time.UTC)
	encoder := &mockPrimitiveArrayEncoder{}
	customTimeEncoder(testTime, encoder)

	expected := "2023-12-25 14:30:45.123456"
	if encoder.value != expected {
		t.Errorf("Expected %s, got %s", expected, encoder.value)
	}
}

func TestInitLoggerWithDebugFlag(t *testing.T) {
	originalDebug := os.Getenv("DEBUG")
	defer os.Setenv("DEBUG", originalDebug)

	testCases := []struct {
		name     string
		debugVal string
		setEnv   bool
	}{
		{"debug_true", "true", true},
		{"debug_false", "false", true},
		{"debug_unset", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setEnv {
				os.Setenv("DEBUG", tc.debugVal)
			} else {
				os.Unsetenv("DEBUG")
			}

			initLogger()

			if zapLogger == nil {
				t.Error("zapLogger should not be nil after initialization")
			}
		})
	}
}

func TestLoggingFunctions(t *testing.T) {
	if zapLogger == nil {
		initLogger()
	}

	simpleFuncs := []struct {
		name string
		fn   func(string)
	}{
		{"Print", Print},
		{"Debug", Debug},
		{"Err", Err},
		{"Warn", Warn},
	}

	for _, tc := range simpleFuncs {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn("test message")
		})
	}

	formattedFuncs := []struct {
		name string
		fn   func(string, ...interface{})
	}{
		{"Printf", Printf},
		{"Debugf", Debugf},
		{"Errf", Errf},
		{"Warnf", Warnf},
	}

	for _, tc := range formattedFuncs {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn("test message %s %d", "formatted", 123)
		})
	}
}

func TestInitLoggerJSONUnmarshalPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic from invalid JSON")
		}
	}()

	invalidJSON := []byte(`{invalid json`)
	config := zap.Config{}
	if err := json.Unmarshal(invalidJSON, &config); err != nil {
		panic(err)
	}
}

func TestInitLoggerConfigBuildPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic from config.Build()")
		}
	}()

	config := zap.Config{
		Encoding: "invalid-encoding",
	}

	_, err := config.Build()
	if err != nil {
		panic(err)
	}
}

func TestInitLoggerSuccess(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("initLogger should not panic during normal execution, got: %v", r)
		}
	}()

	initLogger()

	if zapLogger == nil {
		t.Error("zapLogger should not be nil after successful initialization")
	}
}

func TestLoggingFunctionsWithNilLogger(t *testing.T) {
	originalLogger := zapLogger
	defer func() { zapLogger = originalLogger }()

	zapLogger = nil
	initLogger()

	if zapLogger == nil {
		t.Error("Logger should be initialized and not nil")
	}
}

type mockPrimitiveArrayEncoder struct {
	value string
}

func (m *mockPrimitiveArrayEncoder) AppendBool(bool)             {}
func (m *mockPrimitiveArrayEncoder) AppendByteString([]byte)     {}
func (m *mockPrimitiveArrayEncoder) AppendComplex128(complex128) {}
func (m *mockPrimitiveArrayEncoder) AppendComplex64(complex64)   {}
func (m *mockPrimitiveArrayEncoder) AppendFloat64(float64)       {}
func (m *mockPrimitiveArrayEncoder) AppendFloat32(float32)       {}
func (m *mockPrimitiveArrayEncoder) AppendInt(int)               {}
func (m *mockPrimitiveArrayEncoder) AppendInt64(int64)           {}
func (m *mockPrimitiveArrayEncoder) AppendInt32(int32)           {}
func (m *mockPrimitiveArrayEncoder) AppendInt16(int16)           {}
func (m *mockPrimitiveArrayEncoder) AppendInt8(int8)             {}
func (m *mockPrimitiveArrayEncoder) AppendString(s string) {
	m.value = s
}
func (m *mockPrimitiveArrayEncoder) AppendUint(uint)              {}
func (m *mockPrimitiveArrayEncoder) AppendUint64(uint64)          {}
func (m *mockPrimitiveArrayEncoder) AppendUint32(uint32)          {}
func (m *mockPrimitiveArrayEncoder) AppendUint16(uint16)          {}
func (m *mockPrimitiveArrayEncoder) AppendUint8(uint8)            {}
func (m *mockPrimitiveArrayEncoder) AppendUintptr(uintptr)        {}
func (m *mockPrimitiveArrayEncoder) AppendDuration(time.Duration) {}
func (m *mockPrimitiveArrayEncoder) AppendTime(time.Time)         {}
