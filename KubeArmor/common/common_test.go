// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestClone(t *testing.T) {
	type Source struct {
		Name string
		Age  int
	}
	src := Source{Name: "test", Age: 30}
	var dst Source

	err := Clone(src, &dst)
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}

	if dst.Name != "test" || dst.Age != 30 {
		t.Errorf("Expected dst to be clone of src, got Name=%s, Age=%d", dst.Name, dst.Age)
	}
}

func TestRemoveStringElement(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		index    int
		expected []string
	}{
		{
			name:     "remove middle element",
			slice:    []string{"a", "b", "c"},
			index:    1,
			expected: []string{"a", "c"},
		},
		{
			name:     "remove first element",
			slice:    []string{"a", "b", "c"},
			index:    0,
			expected: []string{"b", "c"},
		},
		{
			name:     "remove last element",
			slice:    []string{"a", "b", "c"},
			index:    2,
			expected: []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := RemoveStringElement(tt.slice, tt.index)
			if !reflect.DeepEqual(res, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, res)
			}
		})
	}
}

func TestContainsElement(t *testing.T) {
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
			name:     "not a slice type",
			slice:    "not a slice",
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

func TestCopyFile(t *testing.T) {
	tempDir := t.TempDir()
	srcFile := filepath.Join(tempDir, "src.txt")
	dstFile := filepath.Join(tempDir, "dst.txt")

	content := []byte("hello world")
	if err := os.WriteFile(srcFile, content, 0600); err != nil {
		t.Fatalf("Failed to write source file: %v", err)
	}

	err := CopyFile(srcFile, dstFile)
	if err != nil {
		t.Fatalf("CopyFile failed: %v", err)
	}

	copiedContent, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("Failed to read destination file: %v", err)
	}

	if string(copiedContent) != string(content) {
		t.Errorf("Expected %s, got %s", content, copiedContent)
	}
}

func TestGetDateTimeNow(t *testing.T) {
	timestamp, str := GetDateTimeNow()
	now := time.Now().Unix()

	// Allow a tiny window of 2 seconds difference for slow runner execution
	if timestamp < now-2 || timestamp > now+2 {
		t.Errorf("Timestamp difference too large: got %d, now %d", timestamp, now)
	}

	if str == "" {
		t.Errorf("Formatted time string is empty")
	}
}
