// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build windows

package util

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/gomega"
	gomegaTypes "github.com/onsi/gomega/types"
)

// shellBuiltins is the set of cmd.exe built-in commands that cannot be run directly.
var shellBuiltins = map[string]bool{
	"echo": true, "type": true, "dir": true, "copy": true, "move": true,
	"del": true, "rd": true, "md": true, "mkdir": true, "rmdir": true,
	"start": true, "set": true, "if": true, "for": true, "call": true,
	"goto": true, "exit": true, "cls": true, "ren": true, "rename": true,
}

// RunWindowsCommand runs a command on Windows. If the first token is a shell
// built-in or the command uses shell operators (>, |, &&), it routes through
// cmd.exe /C; otherwise it executes the binary directly. Running directly
// avoids depending on cmd.exe being unblocked by AppLocker.
func RunWindowsCommand(cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("empty command")
	}

	// Check if we need cmd.exe: shell built-ins or shell operators present.
	needsShell := shellBuiltins[strings.ToLower(cmd[0])]
	if !needsShell {
		for _, arg := range cmd {
			if strings.ContainsAny(arg, "><|&") {
				needsShell = true
				break
			}
		}
	}

	var command *exec.Cmd
	if needsShell {
		// Route through cmd.exe for shell built-ins/operators.
		args := append([]string{"/C"}, strings.Join(cmd, " "))
		command = exec.Command("cmd.exe", args...)
	} else {
		// Run the binary directly — avoids cmd.exe AppLocker dependency.
		command = exec.Command(cmd[0], cmd[1:]...)
	}

	var out bytes.Buffer
	command.Stdout = &out
	command.Stderr = &out

	err := command.Run()
	outStr := strings.TrimSpace(out.String())
	if err != nil {
		return outStr, fmt.Errorf("cmd %v failed: %w, output: %s", cmd, err, outStr)
	}
	return outStr, nil
}

// AssertWindowsCommand runs a Windows command and asserts the combined output
// matches the given Gomega matcher. Set eventual=true to retry for up to 10s.
func AssertWindowsCommand(cmd []string, match gomegaTypes.GomegaMatcher, eventual bool) {
	if eventual {
		Eventually(func() string {
			output, err := RunWindowsCommand(cmd)
			fmt.Printf("---START---\nOUTPUT: %s\nERROR: %v\n---END---\n", output, err)
			if err != nil {
				return strings.Join([]string{output, err.Error()}, "\n")
			}
			return output
		}, 10*time.Second, 2*time.Second).Should(match)
	} else {
		output, err := RunWindowsCommand(cmd)
		fmt.Printf("---START---\nOUTPUT: %s\nERROR: %v\n---END---\n", output, err)
		var combined string
		if err != nil {
			combined = strings.Join([]string{output, err.Error()}, "\n")
		} else {
			combined = output
		}
		Expect(combined).To(match)
	}
}
