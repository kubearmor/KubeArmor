package log

import (
	"testing"

	"go.uber.org/zap"
)

// test if Logger switches to Debug Mode when the environment varible is set to true
func TestLoggerDebugMode(t *testing.T) {
	//ensure debug is true for this test
	t.Setenv("DEBUG", "true")

	initLogger()

	if !zapLogger.Desugar().Core().Enabled(zap.DebugLevel) {
		t.Errorf("Expected Logger to be in debug mode but it wasn't")
	}
}

// test if logger is in INFO mode by default
func TestDefaultLevel(t *testing.T) {
	//ensure debug is unset for this test
	t.Setenv("DEBUG", "")

	initLogger()

	if !zapLogger.Desugar().Core().Enabled(zap.InfoLevel) {
		t.Error("Default Logger should  be in INFO mode")
	}

	if zapLogger.Desugar().Core().Enabled(zap.DebugLevel) {
		t.Error("Default Logger should not be in DEBUG mode")
	}
}

// tests if that DEBUG = True and Debug = TRUE works (case insensitivity for the variable value)
func TestCaseInsensitivity(t *testing.T) {
	inputs := []string{"true", "True", "TRUE"}

	for _, input := range inputs {

		t.Run(input, func(t *testing.T) {
			t.Setenv("DEBUG", input)

			initLogger()

			if !zapLogger.Desugar().Core().Enabled(zap.DebugLevel) {
				t.Errorf("expected DEBUG mode to be enable with input : %s", input)
			}
		})
	}
}
