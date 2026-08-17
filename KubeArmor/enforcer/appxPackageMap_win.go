//go:build windows
// +build windows

package enforcer

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

// AppxPackageInfo holds the package identity information for an installed MSIX/AppX package.
type AppxPackageInfo struct {
	Name              string // Package identity name (e.g. "Microsoft.WindowsNotepad")
	Publisher         string // Publisher DN (e.g. "CN=Microsoft Corporation, ...")
	PackageFamilyName string // e.g. "Microsoft.WindowsNotepad_8wekyb3d8bbwe"
}

// appxPackageMap is the system-wide map of all installed AppX packages,
// keyed by the package identity name (lowercase for case-insensitive lookup).
// It is populated once at startup by buildAppxPackageMap().
var (
	appxPackageMap     map[string]AppxPackageInfo
	appxPackageMapOnce sync.Once
)

// buildAppxPackageMap enumerates all installed AppX/MSIX packages using
// Get-AppxPackage and builds a map keyed by lowercase package identity name.
// This is called once on first use and cached.
func buildAppxPackageMap() map[string]AppxPackageInfo {
	appxPackageMapOnce.Do(func() {
		appxPackageMap = make(map[string]AppxPackageInfo)

		// Use Get-AppxPackage -AllUsers to enumerate all installed packages.
		// We select Name, Publisher, and PackageFamilyName and output as JSON.
		script := `Get-AppxPackage -AllUsers | Select-Object Name, Publisher, PackageFamilyName | ConvertTo-Json -Compress`
		out, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).Output()
		if err != nil {
			fmt.Printf("WARNING: Failed to enumerate AppX packages: %v\n", err)
			return
		}

		// PowerShell may return a single object (not array) if only one package is installed.
		// Handle both cases by wrapping in an array if needed.
		trimmed := strings.TrimSpace(string(out))
		if !strings.HasPrefix(trimmed, "[") {
			trimmed = "[" + trimmed + "]"
		}

		var packages []struct {
			Name              string `json:"Name"`
			Publisher         string `json:"Publisher"`
			PackageFamilyName string `json:"PackageFamilyName"`
		}
		if err := json.Unmarshal([]byte(trimmed), &packages); err != nil {
			fmt.Printf("WARNING: Failed to parse AppX package list: %v\n", err)
			return
		}

		for _, p := range packages {
			if p.Name == "" {
				continue
			}
			appxPackageMap[strings.ToLower(p.Name)] = AppxPackageInfo{
				Name:              p.Name,
				Publisher:         p.Publisher,
				PackageFamilyName: p.PackageFamilyName,
			}
		}

		fmt.Printf("INFO: AppX package map initialized with %d packages\n", len(appxPackageMap))
	})
	return appxPackageMap
}

// resolvePackageMatches takes a user-specified name pattern (treated as a regex,
// e.g. ".*Notepad.*" or "Microsoft.Windows.*") and matches it case-insensitively
// against all known AppX package identity names. It returns all matching packages.
//
// If publisher is also specified, it is used as an additional filter (AND).
// If name is empty or "*", all packages are returned (optionally filtered by publisher).
func resolvePackageMatches(namePattern string, publisherFilter string) []AppxPackageInfo {
	pkgMap := buildAppxPackageMap()

	// Normalize pattern: treat bare "*" as "match all"
	if namePattern == "" || namePattern == "*" {
		namePattern = ".*"
	}

	// Convert glob-style patterns to regex: if the pattern contains no regex
	// metacharacters other than * and ?, treat * as .* and ? as .
	// If it already looks like a regex (contains . + [ etc), use as-is.
	pattern := globToRegex(namePattern)

	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		fmt.Printf("WARNING: Invalid package name pattern '%s': %v — using literal match\n", namePattern, err)
		// Fall back to literal substring match
		literal := strings.ToLower(namePattern)
		var results []AppxPackageInfo
		for _, pkg := range pkgMap {
			if strings.Contains(strings.ToLower(pkg.Name), literal) {
				if publisherFilter == "" || strings.EqualFold(pkg.Publisher, publisherFilter) {
					results = append(results, pkg)
				}
			}
		}
		return results
	}

	var matches []AppxPackageInfo
	for _, pkg := range pkgMap {
		if re.MatchString(pkg.Name) {
			if publisherFilter == "" || strings.EqualFold(pkg.Publisher, publisherFilter) {
				matches = append(matches, pkg)
			}
		}
	}
	return matches
}

// globToRegex converts a simple glob pattern (with * and ?) into a full regex.
// If the input already contains regex metacharacters (like . + [ { ) it is
// returned as-is, assuming the user intentionally wrote a regex.
func globToRegex(pattern string) string {
	// If it looks like a plain glob (only contains *, ?, letters, digits, dots
	// that are package-name separators, and hyphens), convert it.
	// Otherwise treat it as a regex directly.
	isGlob := true
	for _, c := range pattern {
		if c == '+' || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}' || c == '^' || c == '$' || c == '|' || c == '\\' {
			isGlob = false
			break
		}
	}

	if isGlob {
		// Escape dots (package name separators) and convert glob wildcards
		var sb strings.Builder
		sb.WriteString("^")
		for _, c := range pattern {
			switch c {
			case '.':
				sb.WriteString(`\.`)
			case '*':
				sb.WriteString(`.*`)
			case '?':
				sb.WriteString(`.`)
			default:
				sb.WriteRune(c)
			}
		}
		sb.WriteString("$")
		return sb.String()
	}

	return pattern
}
