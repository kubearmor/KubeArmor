// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestContainsElement(t *testing.T) {
	type CustomStruct struct {
		ID int
	}

	tests := []struct {
		name     string
		slice    interface{}
		element  interface{}
		expected bool
	}{
		{
			name:     "element exists in string slice",
			slice:    []string{"a", "b", "c"},
			element:  "b",
			expected: true,
		},
		{
			name:     "element does not exist in string slice",
			slice:    []string{"a", "b", "c"},
			element:  "d",
			expected: false,
		},
		{
			name:     "element exists in int slice",
			slice:    []int{1, 2, 3},
			element:  2,
			expected: true,
		},
		{
			name:     "element exists in struct slice",
			slice:    []CustomStruct{{ID: 1}, {ID: 2}},
			element:  CustomStruct{ID: 2},
			expected: true,
		},
		{
			name:     "not a slice type",
			slice:    "not a slice",
			element:  "a",
			expected: false,
		},
		{
			name:     "nil slice argument",
			slice:    nil,
			element:  "a",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ContainsElement(tt.slice, tt.element)
			if res != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, res)
			}
		})
	}
}

func TestMatchesRegex(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		element  string
		array    []string
		expected bool
	}{
		{
			name:     "regex matches item containing key",
			key:      "test",
			element:  "^test-[a-z]+$",
			array:    []string{"test-abc", "other"},
			expected: true,
		},
		{
			name:     "regex does not match item containing key",
			key:      "test",
			element:  "^test-[0-9]+$",
			array:    []string{"test-abc", "other"},
			expected: false,
		},
		{
			name:     "key not found in array",
			key:      "missing",
			element:  "^.*$",
			array:    []string{"test-abc", "other"},
			expected: true,
		},
		{
			name:     "invalid regex",
			key:      "test",
			element:  "[invalid",
			array:    []string{"test-abc"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := MatchesRegex(tt.key, tt.element, tt.array)
			if res != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, res)
			}
		})
	}
}

type MockCommaStruct struct {
	Value string
	Data  int
}

func TestObjCommaExpandAndHelpers(t *testing.T) {
	t.Run("ObjCommaCanBeExpanded", func(t *testing.T) {
		sliceWithComma := []MockCommaStruct{{Value: "a,b", Data: 1}}
		sliceNoComma := []MockCommaStruct{{Value: "a", Data: 2}}
		notSlice := MockCommaStruct{Value: "a,b", Data: 1}
		emptySlice := []MockCommaStruct{}

		if !ObjCommaCanBeExpanded(&sliceWithComma) {
			t.Errorf("Expected sliceWithComma to be expandable")
		}
		if ObjCommaCanBeExpanded(&sliceNoComma) {
			t.Errorf("Expected sliceNoComma to not be expandable")
		}
		if ObjCommaCanBeExpanded(notSlice) {
			t.Errorf("Expected non-ptr to not be expandable")
		}
		if ObjCommaCanBeExpanded(&emptySlice) {
			t.Errorf("Expected empty slice to not be expandable")
		}
	})

	t.Run("ObjCommaExpandFirstDupOthers", func(t *testing.T) {
		slice := []MockCommaStruct{
			{Value: "a,b,c", Data: 42},
			{Value: "d", Data: 100},
		}

		ObjCommaExpandFirstDupOthers(&slice)

		expected := []MockCommaStruct{
			{Value: "a", Data: 42},
			{Value: "b", Data: 42},
			{Value: "c", Data: 42},
			{Value: "d", Data: 100},
		}

		if !reflect.DeepEqual(slice, expected) {
			t.Errorf("Expected %v, got %v", expected, slice)
		}
	})
}

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid IPv4",
			input:    "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "valid IPv6",
			input:    "2001:db8::1",
			expected: "[2001:db8::1]",
		},
		{
			name:     "IPv6-mapped IPv4",
			input:    "::ffff:192.168.1.1",
			expected: "[::ffff:192.168.1.1]",
		},
		{
			name:     "invalid IP string",
			input:    "invalid-ip",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := NormalizeIP(tt.input)
			if res != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, res)
			}
		})
	}
}

func TestGetLabelsFromString(t *testing.T) {
	labelStr := "b=two,a=one,c=three"

	expectedMap := map[string]string{
		"a": "one",
		"b": "two",
		"c": "three",
	}
	expectedSlice := []string{"a=one", "b=two", "c=three"}

	gotMap, gotSlice := GetLabelsFromString(labelStr)

	if !reflect.DeepEqual(gotMap, expectedMap) {
		t.Errorf("Expected map %v, got %v", expectedMap, gotMap)
	}
	if !reflect.DeepEqual(gotSlice, expectedSlice) {
		t.Errorf("Expected slice %v, got %v", expectedSlice, gotSlice)
	}
}

func TestRemoveSafeAndRemoveAllSafe(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "testfile.txt")

	if err := os.WriteFile(tempFile, []byte("data"), 0600); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Test safe file deletion
	if err := RemoveSafe(tempFile); err != nil {
		t.Errorf("Expected safe removal to succeed, got %v", err)
	}

	// Test unsafe paths
	unsafePaths := []string{"", "/", string(filepath.Separator)}
	for _, path := range unsafePaths {
		if err := RemoveSafe(path); err != errUnsafePathToRemove {
			t.Errorf("Expected errUnsafePathToRemove for path %q, got %v", path, err)
		}
		if err := RemoveAllSafe(path); err != errUnsafePathToRemove {
			t.Errorf("Expected errUnsafePathToRemove for RemoveAllSafe on path %q, got %v", path, err)
		}
	}
}

func TestParseURL(t *testing.T) {
	tests := []struct {
		name         string
		address      string
		expectedHost string
		expectedPort string
		expectErr    bool
	}{
		{
			name:         "URL with scheme and port",
			address:      "http://example.com:8080",
			expectedHost: "example.com",
			expectedPort: "8080",
			expectErr:    false,
		},
		{
			name:         "URL without scheme with port",
			address:      "example.com:9000",
			expectedHost: "example.com",
			expectedPort: "9000",
			expectErr:    false,
		},
		{
			name:         "URL without scheme or port",
			address:      "example.com",
			expectedHost: "example.com",
			expectedPort: "80",
			expectErr:    false,
		},
		{
			name:      "Invalid URL",
			address:   "http://invalid url:80",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := ParseURL(tt.address)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for address %q, got nil", tt.address)
				}
			} else {
				if err != nil {
					t.Fatalf("ParseURL failed: %v", err)
				}
				if host != tt.expectedHost || port != tt.expectedPort {
					t.Errorf("Expected host %q port %q, got host %q port %q", tt.expectedHost, tt.expectedPort, host, port)
				}
			}
		})
	}
}

func TestGetSHA256ofImage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "image with digest tag",
			input:    "ubuntu@sha256:1234567890abcdef",
			expected: "@sha256:1234567890abcdef",
		},
		{
			name:     "image without digest",
			input:    "ubuntu:latest",
			expected: "ubuntu:latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := GetSHA256ofImage(tt.input)
			if res != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, res)
			}
		})
	}
}

func TestMatchIdentities(t *testing.T) {
	tests := []struct {
		name            string
		identities      []string
		superIdentities []string
		expected        bool
	}{
		{
			name:            "empty identities",
			identities:      []string{},
			superIdentities: []string{"env=prod"},
			expected:        false,
		},
		{
			name:            "exact identity match",
			identities:      []string{"env=prod", "app=nginx"},
			superIdentities: []string{"env=prod", "app=nginx", "tier=frontend"},
			expected:        true,
		},
		{
			name:            "missing identity",
			identities:      []string{"env=prod", "app=redis"},
			superIdentities: []string{"env=prod", "app=nginx"},
			expected:        false,
		},
		{
			name:            "container name regex identity match",
			identities:      []string{"kubearmor.io/container.name=^web-[0-9]+$"},
			superIdentities: []string{"kubearmor.io/container.name=web-123"},
			expected:        true,
		},
		{
			name:            "hostname regex pattern match",
			identities:      []string{"kubearmor.io/hostnamereg=node-*"},
			superIdentities: []string{"kubearmor.io/hostname=node-42"},
			expected:        true,
		},
		{
			name:            "comma separated hostname match",
			identities:      []string{"kubearmor.io/hostname=node-1,node-2"},
			superIdentities: []string{"kubearmor.io/hostname=node-2"},
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := MatchIdentities(tt.identities, tt.superIdentities)
			if res != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, res)
			}
		})
	}
}

func TestMatchExpIdentities(t *testing.T) {
	tests := []struct {
		name            string
		selector        tp.SelectorType
		superIdentities []string
		expected        bool
	}{
		{
			name:            "empty selector identities",
			selector:        tp.SelectorType{},
			superIdentities: []string{"env=prod"},
			expected:        true,
		},
		{
			name: "match exp identity present",
			selector: tp.SelectorType{
				MatchExpIdentities: []string{"env=prod"},
			},
			superIdentities: []string{"env=prod", "app=nginx"},
			expected:        true,
		},
		{
			name: "non-identity excluded",
			selector: tp.SelectorType{
				NonIdentities: []string{"env=test"},
			},
			superIdentities: []string{"env=test"},
			expected:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := MatchExpIdentities(tt.selector, tt.superIdentities)
			if res != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, res)
			}
		})
	}
}
