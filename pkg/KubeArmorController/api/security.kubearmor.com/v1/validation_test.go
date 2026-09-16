package v1

import (
	"strings"
	"testing"
)

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		expectErrors   bool
		expectWarnings bool
		errorContains  string
	}{
		{
			name:         "valid absolute path",
			path:         "/usr/bin/bash",
			expectErrors: false,
		},
		{
			name:         "valid root path",
			path:         "/",
			expectErrors: false,
		},
		{
			name:          "empty path",
			path:          "",
			expectErrors:  true,
			errorContains: "cannot be empty",
		},
		{
			name:          "relative path",
			path:          "usr/bin/bash",
			expectErrors:  true,
			errorContains: "must be absolute",
		},
		{
			name:          "path with null byte",
			path:          "/etc/passwd\x00hidden",
			expectErrors:  true,
			errorContains: "invalid control character",
		},
		{
			name:          "path with control character",
			path:          "/etc/\x1fpasswd",
			expectErrors:  true,
			errorContains: "invalid control character",
		},
		{
			name:           "path with double slash",
			path:           "/etc//passwd",
			expectWarnings: true,
		},
		{
			name:           "path with path traversal",
			path:           "/etc/../passwd",
			expectWarnings: true,
		},
		{
			name:          "path too long",
			path:          "/" + strings.Repeat("a", MaxPathLength),
			expectErrors:  true,
			errorContains: "exceeds maximum length",
		},
		{
			name:         "path at max length",
			path:         "/" + strings.Repeat("a", MaxPathLength-2),
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePath(tt.path, "test.path")

			if tt.expectErrors && !result.HasErrors() {
				t.Errorf("expected errors but got none")
			}
			if !tt.expectErrors && result.HasErrors() {
				t.Errorf("expected no errors but got: %s", result.ErrorMessages())
			}
			if tt.expectWarnings && !result.HasWarnings() {
				t.Errorf("expected warnings but got none")
			}
			if tt.errorContains != "" {
				found := false
				for _, err := range result.Errors {
					if strings.Contains(err.Message, tt.errorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing '%s' but got: %s", tt.errorContains, result.ErrorMessages())
				}
			}
		})
	}
}

func TestValidateDirectory(t *testing.T) {
	tests := []struct {
		name           string
		dir            string
		expectErrors   bool
		expectWarnings bool
	}{
		{
			name:         "valid directory with trailing slash",
			dir:          "/usr/bin/",
			expectErrors: false,
		},
		{
			name:         "root directory",
			dir:          "/",
			expectErrors: false,
		},
		{
			name:           "directory without trailing slash",
			dir:            "/usr/bin",
			expectWarnings: true,
		},
		{
			name:         "relative directory",
			dir:          "usr/bin/",
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateDirectory(tt.dir, "test.dir")

			if tt.expectErrors && !result.HasErrors() {
				t.Errorf("expected errors but got none")
			}
			if !tt.expectErrors && result.HasErrors() {
				t.Errorf("expected no errors but got: %s", result.ErrorMessages())
			}
			if tt.expectWarnings && !result.HasWarnings() {
				t.Errorf("expected warnings but got none")
			}
		})
	}
}

func TestValidatePattern(t *testing.T) {
	tests := []struct {
		name          string
		pattern       string
		expectErrors  bool
		errorContains string
	}{
		{
			name:         "valid simple pattern",
			pattern:      ".*\\.txt",
			expectErrors: false,
		},
		{
			name:         "valid complex pattern",
			pattern:      "^/usr/bin/[a-z]+$",
			expectErrors: false,
		},
		{
			name:          "empty pattern",
			pattern:       "",
			expectErrors:  true,
			errorContains: "cannot be empty",
		},
		{
			name:          "invalid regex - unclosed group",
			pattern:       "*.txt(",
			expectErrors:  true,
			errorContains: "invalid regex",
		},
		{
			name:          "invalid regex - unclosed bracket",
			pattern:       "[abc",
			expectErrors:  true,
			errorContains: "invalid regex",
		},
		{
			name:          "pattern too long",
			pattern:       strings.Repeat("a", MaxPatternLength+1),
			expectErrors:  true,
			errorContains: "exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePattern(tt.pattern, "test.pattern")

			if tt.expectErrors && !result.HasErrors() {
				t.Errorf("expected errors but got none")
			}
			if !tt.expectErrors && result.HasErrors() {
				t.Errorf("expected no errors but got: %s", result.ErrorMessages())
			}
			if tt.errorContains != "" {
				found := false
				for _, err := range result.Errors {
					if strings.Contains(err.Message, tt.errorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error containing '%s' but got: %s", tt.errorContains, result.ErrorMessages())
				}
			}
		})
	}
}

func TestValidateProcessType(t *testing.T) {
	tests := []struct {
		name           string
		process        ProcessType
		expectErrors   bool
		expectWarnings bool
	}{
		{
			name: "valid process with paths",
			process: ProcessType{
				MatchPaths: []ProcessPathType{
					{Path: "/usr/bin/bash"},
					{Path: "/usr/bin/sh"},
				},
			},
			expectErrors: false,
		},
		{
			name: "duplicate paths",
			process: ProcessType{
				MatchPaths: []ProcessPathType{
					{Path: "/usr/bin/bash"},
					{Path: "/usr/bin/bash"},
				},
			},
			expectWarnings: true,
		},
		{
			name: "invalid path in process",
			process: ProcessType{
				MatchPaths: []ProcessPathType{
					{Path: "relative/path"},
				},
			},
			expectErrors: true,
		},
		{
			name: "valid directory with trailing slash",
			process: ProcessType{
				MatchDirectories: []ProcessDirectoryType{
					{Directory: "/usr/bin/"},
				},
			},
			expectErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateProcessType(tt.process, "spec.process")

			if tt.expectErrors && !result.HasErrors() {
				t.Errorf("expected errors but got none")
			}
			if !tt.expectErrors && result.HasErrors() {
				t.Errorf("expected no errors but got: %s", result.ErrorMessages())
			}
			if tt.expectWarnings && !result.HasWarnings() {
				t.Errorf("expected warnings but got none")
			}
		})
	}
}

func TestValidateFileType(t *testing.T) {
	tests := []struct {
		name           string
		file           FileType
		expectErrors   bool
		expectWarnings bool
	}{
		{
			name: "valid file paths",
			file: FileType{
				MatchPaths: []FilePathType{
					{Path: "/etc/passwd"},
					{Path: "/etc/shadow"},
				},
			},
			expectErrors: false,
		},
		{
			name: "duplicate file paths",
			file: FileType{
				MatchPaths: []FilePathType{
					{Path: "/etc/passwd"},
					{Path: "/etc/passwd"},
				},
			},
			expectWarnings: true,
		},
		{
			name: "path too long",
			file: FileType{
				MatchPaths: []FilePathType{
					{Path: MatchPathType("/" + strings.Repeat("a", MaxPathLength))},
				},
			},
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateFileType(tt.file, "spec.file")

			if tt.expectErrors && !result.HasErrors() {
				t.Errorf("expected errors but got none")
			}
			if !tt.expectErrors && result.HasErrors() {
				t.Errorf("expected no errors but got: %s", result.ErrorMessages())
			}
			if tt.expectWarnings && !result.HasWarnings() {
				t.Errorf("expected warnings but got none")
			}
		})
	}
}

func TestCountRules(t *testing.T) {
	spec := KubeArmorPolicySpec{
		Process: ProcessType{
			MatchPaths: []ProcessPathType{
				{Path: "/usr/bin/bash"},
				{Path: "/usr/bin/sh"},
			},
			MatchDirectories: []ProcessDirectoryType{
				{Directory: "/usr/bin/"},
			},
		},
		File: FileType{
			MatchPaths: []FilePathType{
				{Path: "/etc/passwd"},
			},
		},
		Network: NetworkType{
			MatchProtocols: []MatchNetworkProtocolType{
				{Protocol: "tcp"},
			},
		},
	}

	count := CountRules(spec)
	expectedCount := 5

	if count != expectedCount {
		t.Errorf("expected %d rules but got %d", expectedCount, count)
	}
}

func TestValidateKubeArmorPolicy(t *testing.T) {
	tests := []struct {
		name           string
		policy         *KubeArmorPolicy
		expectErrors   bool
		expectWarnings bool
	}{
		{
			name:         "nil policy",
			policy:       nil,
			expectErrors: true,
		},
		{
			name: "valid policy with selector",
			policy: &KubeArmorPolicy{
				Spec: KubeArmorPolicySpec{
					Selector: SelectorType{
						MatchLabels: map[string]string{"app": "test"},
					},
					Process: ProcessType{
						MatchPaths: []ProcessPathType{
							{Path: "/usr/bin/bash"},
						},
					},
				},
			},
			expectErrors: false,
		},
		{
			name: "policy without selector labels",
			policy: &KubeArmorPolicy{
				Spec: KubeArmorPolicySpec{
					Selector: SelectorType{},
					Process: ProcessType{
						MatchPaths: []ProcessPathType{
							{Path: "/usr/bin/bash"},
						},
					},
				},
			},
			expectWarnings: true,
		},
		{
			name: "policy with invalid path",
			policy: &KubeArmorPolicy{
				Spec: KubeArmorPolicySpec{
					Selector: SelectorType{
						MatchLabels: map[string]string{"app": "test"},
					},
					Process: ProcessType{
						MatchPaths: []ProcessPathType{
							{Path: "relative/path"},
						},
					},
				},
			},
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateKubeArmorPolicy(tt.policy)

			if tt.expectErrors && !result.HasErrors() {
				t.Errorf("expected errors but got none")
			}
			if !tt.expectErrors && result.HasErrors() {
				t.Errorf("expected no errors but got: %s", result.ErrorMessages())
			}
			if tt.expectWarnings && !result.HasWarnings() {
				t.Errorf("expected warnings but got none")
			}
		})
	}
}

func TestTruncatePath(t *testing.T) {
	tests := []struct {
		path     string
		maxLen   int
		expected string
	}{
		{
			path:     "/short/path",
			maxLen:   50,
			expected: "/short/path",
		},
		{
			path:     "/very/long/path/that/exceeds/the/limit",
			maxLen:   20,
			expected: "/very/long/path/that...",
		},
	}

	for _, tt := range tests {
		result := truncatePath(tt.path, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncatePath(%s, %d) = %s; want %s", tt.path, tt.maxLen, result, tt.expected)
		}
	}
}
