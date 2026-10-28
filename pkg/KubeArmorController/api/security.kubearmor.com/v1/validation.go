package v1

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	MaxPathLength        = 256
	MaxCombinedLength    = 4096
	MaxRulesPerContainer = 512
	MaxPatternLength     = 512
)

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
}

func (r *ValidationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

func (r *ValidationResult) HasWarnings() bool {
	return len(r.Warnings) > 0
}

func (r *ValidationResult) AddError(field, message string) {
	r.Errors = append(r.Errors, ValidationError{Field: field, Message: message})
}

func (r *ValidationResult) AddWarning(field, message string) {
	r.Warnings = append(r.Warnings, ValidationError{Field: field, Message: message})
}

func (r *ValidationResult) ErrorMessages() string {
	if len(r.Errors) == 0 {
		return ""
	}
	var msgs []string
	for _, e := range r.Errors {
		msgs = append(msgs, e.Error())
	}
	return strings.Join(msgs, "; ")
}

func (r *ValidationResult) WarningMessages() string {
	if len(r.Warnings) == 0 {
		return ""
	}
	var msgs []string
	for _, w := range r.Warnings {
		msgs = append(msgs, w.Error())
	}
	return strings.Join(msgs, "; ")
}

var invalidPathChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func ValidatePath(path string, fieldName string) *ValidationResult {
	result := &ValidationResult{}

	if path == "" {
		result.AddError(fieldName, "path cannot be empty")
		return result
	}

	if !strings.HasPrefix(path, "/") {
		result.AddError(fieldName, fmt.Sprintf("path must be absolute (start with /), got: %s", path))
	}

	if len(path) > MaxPathLength {
		result.AddError(fieldName, fmt.Sprintf("path exceeds maximum length of %d characters (got %d): %s...",
			MaxPathLength, len(path), truncatePath(path, 50)))
	}

	if invalidPathChars.MatchString(path) {
		loc := invalidPathChars.FindStringIndex(path)
		if loc != nil {
			result.AddError(fieldName, fmt.Sprintf("path contains invalid control character at position %d", loc[0]))
		} else {
			result.AddError(fieldName, "path contains invalid control characters")
		}
	}

	if strings.Contains(path, "..") {
		result.AddWarning(fieldName, fmt.Sprintf("path contains '..' which may indicate path traversal: %s", path))
	}

	if strings.Contains(path, "//") {
		result.AddWarning(fieldName, fmt.Sprintf("path contains double slashes '//': %s", path))
	}

	return result
}

func ValidateDirectory(dir string, fieldName string) *ValidationResult {
	result := ValidatePath(dir, fieldName)

	if dir != "" && !strings.HasSuffix(dir, "/") {
		result.AddWarning(fieldName, fmt.Sprintf("directory path should end with '/': %s", dir))
	}

	return result
}

func ValidatePattern(pattern string, fieldName string) *ValidationResult {
	result := &ValidationResult{}

	if pattern == "" {
		result.AddError(fieldName, "pattern cannot be empty")
		return result
	}

	if len(pattern) > MaxPatternLength {
		result.AddError(fieldName, fmt.Sprintf("pattern exceeds maximum length of %d characters (got %d)",
			MaxPatternLength, len(pattern)))
	}

	_, err := regexp.Compile(pattern)
	if err != nil {
		result.AddError(fieldName, fmt.Sprintf("invalid regex pattern: %v", err))
	}

	return result
}

func ValidateProcessType(process ProcessType, fieldPrefix string) *ValidationResult {
	result := &ValidationResult{}
	seenPaths := make(map[string]bool)

	for i, pathRule := range process.MatchPaths {
		fieldName := fmt.Sprintf("%s.matchPaths[%d].path", fieldPrefix, i)
		pathStr := string(pathRule.Path)

		if seenPaths[pathStr] {
			result.AddWarning(fieldName, fmt.Sprintf("duplicate path detected: %s", pathStr))
		}
		seenPaths[pathStr] = true

		pathResult := ValidatePath(pathStr, fieldName)
		result.Errors = append(result.Errors, pathResult.Errors...)
		result.Warnings = append(result.Warnings, pathResult.Warnings...)

		for j, src := range pathRule.FromSource {
			srcFieldName := fmt.Sprintf("%s.matchPaths[%d].fromSource[%d].path", fieldPrefix, i, j)
			srcResult := ValidatePath(string(src.Path), srcFieldName)
			result.Errors = append(result.Errors, srcResult.Errors...)
			result.Warnings = append(result.Warnings, srcResult.Warnings...)
		}
	}

	seenDirs := make(map[string]bool)
	for i, dirRule := range process.MatchDirectories {
		fieldName := fmt.Sprintf("%s.matchDirectories[%d].dir", fieldPrefix, i)
		dirStr := string(dirRule.Directory)

		if seenDirs[dirStr] {
			result.AddWarning(fieldName, fmt.Sprintf("duplicate directory detected: %s", dirStr))
		}
		seenDirs[dirStr] = true

		dirResult := ValidateDirectory(dirStr, fieldName)
		result.Errors = append(result.Errors, dirResult.Errors...)
		result.Warnings = append(result.Warnings, dirResult.Warnings...)
	}

	for i, patternRule := range process.MatchPatterns {
		fieldName := fmt.Sprintf("%s.matchPatterns[%d].pattern", fieldPrefix, i)
		patternResult := ValidatePattern(patternRule.Pattern, fieldName)
		result.Errors = append(result.Errors, patternResult.Errors...)
		result.Warnings = append(result.Warnings, patternResult.Warnings...)
	}

	return result
}

func ValidateFileType(file FileType, fieldPrefix string) *ValidationResult {
	result := &ValidationResult{}
	seenPaths := make(map[string]bool)

	for i, pathRule := range file.MatchPaths {
		fieldName := fmt.Sprintf("%s.matchPaths[%d].path", fieldPrefix, i)
		pathStr := string(pathRule.Path)

		if seenPaths[pathStr] {
			result.AddWarning(fieldName, fmt.Sprintf("duplicate path detected: %s", pathStr))
		}
		seenPaths[pathStr] = true

		pathResult := ValidatePath(pathStr, fieldName)
		result.Errors = append(result.Errors, pathResult.Errors...)
		result.Warnings = append(result.Warnings, pathResult.Warnings...)
	}

	seenDirs := make(map[string]bool)
	for i, dirRule := range file.MatchDirectories {
		fieldName := fmt.Sprintf("%s.matchDirectories[%d].dir", fieldPrefix, i)
		dirStr := string(dirRule.Directory)

		if seenDirs[dirStr] {
			result.AddWarning(fieldName, fmt.Sprintf("duplicate directory detected: %s", dirStr))
		}
		seenDirs[dirStr] = true

		dirResult := ValidateDirectory(dirStr, fieldName)
		result.Errors = append(result.Errors, dirResult.Errors...)
		result.Warnings = append(result.Warnings, dirResult.Warnings...)
	}

	for i, patternRule := range file.MatchPatterns {
		fieldName := fmt.Sprintf("%s.matchPatterns[%d].pattern", fieldPrefix, i)
		patternResult := ValidatePattern(patternRule.Pattern, fieldName)
		result.Errors = append(result.Errors, patternResult.Errors...)
		result.Warnings = append(result.Warnings, patternResult.Warnings...)
	}

	return result
}

func ValidateSyscallsType(syscalls SyscallsType, fieldPrefix string) *ValidationResult {
	result := &ValidationResult{}

	for i, pathRule := range syscalls.MatchPaths {
		fieldName := fmt.Sprintf("%s.matchPaths[%d].path", fieldPrefix, i)
		pathStr := string(pathRule.Path)
		pathResult := ValidatePath(pathStr, fieldName)
		result.Errors = append(result.Errors, pathResult.Errors...)
		result.Warnings = append(result.Warnings, pathResult.Warnings...)
	}

	return result
}

func CountRules(spec KubeArmorPolicySpec) int {
	count := 0
	count += len(spec.Process.MatchPaths)
	count += len(spec.Process.MatchDirectories)
	count += len(spec.Process.MatchPatterns)
	count += len(spec.File.MatchPaths)
	count += len(spec.File.MatchDirectories)
	count += len(spec.File.MatchPatterns)
	count += len(spec.Network.MatchProtocols)
	count += len(spec.Capabilities.MatchCapabilities)
	count += len(spec.Syscalls.MatchSyscalls)
	count += len(spec.Syscalls.MatchPaths)
	return count
}

func ValidateKubeArmorPolicy(policy *KubeArmorPolicy) *ValidationResult {
	result := &ValidationResult{}

	if policy == nil {
		result.AddError("policy", "policy cannot be nil")
		return result
	}

	if len(policy.Spec.Selector.MatchLabels) == 0 {
		result.AddWarning("spec.selector.matchLabels", "no labels specified in selector - policy may not match any pods")
	}

	processResult := ValidateProcessType(policy.Spec.Process, "spec.process")
	result.Errors = append(result.Errors, processResult.Errors...)
	result.Warnings = append(result.Warnings, processResult.Warnings...)

	fileResult := ValidateFileType(policy.Spec.File, "spec.file")
	result.Errors = append(result.Errors, fileResult.Errors...)
	result.Warnings = append(result.Warnings, fileResult.Warnings...)

	syscallResult := ValidateSyscallsType(policy.Spec.Syscalls, "spec.syscalls")
	result.Errors = append(result.Errors, syscallResult.Errors...)
	result.Warnings = append(result.Warnings, syscallResult.Warnings...)

	ruleCount := CountRules(policy.Spec)
	if ruleCount > MaxRulesPerContainer {
		result.AddWarning("spec", fmt.Sprintf("policy contains %d rules which exceeds recommended maximum of %d",
			ruleCount, MaxRulesPerContainer))
	}

	return result
}

func ValidateKubeArmorHostPolicy(policy *KubeArmorHostPolicy) *ValidationResult {
	result := &ValidationResult{}

	if policy == nil {
		result.AddError("policy", "policy cannot be nil")
		return result
	}

	if len(policy.Spec.NodeSelector.MatchLabels) == 0 {
		result.AddWarning("spec.nodeSelector.matchLabels", "no labels specified in nodeSelector - policy may not match any nodes")
	}

	processResult := ValidateProcessType(policy.Spec.Process, "spec.process")
	result.Errors = append(result.Errors, processResult.Errors...)
	result.Warnings = append(result.Warnings, processResult.Warnings...)

	fileResult := ValidateFileType(policy.Spec.File, "spec.file")
	result.Errors = append(result.Errors, fileResult.Errors...)
	result.Warnings = append(result.Warnings, fileResult.Warnings...)

	return result
}

func ValidateKubeArmorClusterPolicy(policy *KubeArmorClusterPolicy) *ValidationResult {
	result := &ValidationResult{}

	if policy == nil {
		result.AddError("policy", "policy cannot be nil")
		return result
	}

	if len(policy.Spec.Selector.MatchExpressions) == 0 {
		result.AddWarning("spec.selector.matchExpressions", "no matchExpressions specified in selector")
	}

	processResult := ValidateProcessType(policy.Spec.Process, "spec.process")
	result.Errors = append(result.Errors, processResult.Errors...)
	result.Warnings = append(result.Warnings, processResult.Warnings...)

	fileResult := ValidateFileType(policy.Spec.File, "spec.file")
	result.Errors = append(result.Errors, fileResult.Errors...)
	result.Warnings = append(result.Warnings, fileResult.Warnings...)

	syscallResult := ValidateSyscallsType(policy.Spec.Syscalls, "spec.syscalls")
	result.Errors = append(result.Errors, syscallResult.Errors...)
	result.Warnings = append(result.Warnings, syscallResult.Warnings...)

	return result
}

func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	return path[:maxLen] + "..."
}
