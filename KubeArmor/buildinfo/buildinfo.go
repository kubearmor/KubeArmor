package buildinfo

import (
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

// GitSummary represents build-time info for git commit,tag
var GitSummary string

// GitBranch represents build-time info for git branch
var GitBranch string

// BuildDate represents build-time info for build date
var BuildDate string

func PrintBuildDetails() {
	if GitSummary == "" {
		return
	}
	kg.Printf("BUILD-INFO: version: %v, branch: %v, date: %v",
		GitSummary, GitBranch, BuildDate)
}