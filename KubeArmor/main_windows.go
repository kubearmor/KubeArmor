//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/kubearmor/KubeArmor/KubeArmor/buildinfo"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/core"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

const (
	svcName         = "KubeArmorSvc"
	svcDesc         = "Runtime security enforcement engine using eBPF and LSM."
	svcPollTimeout  = 10 * time.Second
	svcPollInterval = 300 * time.Millisecond
)

func init() {
	buildinfo.PrintBuildDetails()
}

// ================================
// ======= Service handler ========
// ================================

type kubeArmorService struct{}

func (s *kubeArmorService) Execute(
	args []string,
	requests <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (svcSpecificEC bool, exitCode uint32) {

	status <- svc.Status{State: svc.StartPending}

	if err := windowsPreflight(); err != nil {
		kg.Errf("Preflight failed: %v", err)
		status <- svc.Status{State: svc.StopPending}
		return false, 1
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		core.KubeArmor()
	}()

	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue,
	}

	elog, err := eventlog.Open(svcName)
	if err != nil {
		// fall back to file log
		return false, 1
	}
	defer elog.Close()

loop:
	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				if core.Daemon != nil {
					elog.Info(1, "KubeArmor service stopping...")
					core.Daemon.DestroyKubeArmorDaemon()
					elog.Info(1, "KubeArmor service stopped")
				}
				// Wait for core.KubeArmor() goroutine to exit
				elog.Info(2, "Waiting for core goroutine to exit")
				<-done
				elog.Info(2, "Core goroutine exited")

				// Tell SCM we are fully stopped
				status <- svc.Status{State: svc.Stopped}
				elog.Info(2, "Service stopped")
				break loop

			case svc.Pause:
				// KubeArmor does not support true pause/resume at the
				// process level, so we acknowledge it but stay running
				status <- svc.Status{
					State:   svc.Paused,
					Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue,
				}

			case svc.Continue:
				status <- svc.Status{
					State:   svc.Running,
					Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue,
				}

			case svc.Interrogate:
				status <- req.CurrentStatus

			default:
				kg.Warnf("Unexpected SCM control request: %d", req.Cmd)
			}

		case <-done:
			break loop
		}
	}

	return false, 0
}

// ==============================
// ========= Preflight ==========
// ==============================

func windowsPreflight() error {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return fmt.Errorf("failed to resolve binary dir: %w", err)
	}
	if err := os.Chdir(dir); err != nil {
		return fmt.Errorf("failed to set working directory: %w", err)
	}
	if err := cfg.LoadConfig(); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	return nil
}

// ================================
// ========= SCM helpers ==========
// ================================

func openSCM() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("could not connect to SCM: %w", err)
	}
	s, err := m.OpenService(svcName)
	if err != nil {
		m.Disconnect()
		return nil, nil, fmt.Errorf("service %q not found — is it installed?: %w", svcName, err)
	}
	return m, s, nil
}

// waitForState polls until the service reaches wantState or the timeout elapses.
func waitForState(s *mgr.Service, wantState svc.State) error {
	deadline := time.Now().Add(svcPollTimeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return fmt.Errorf("could not query service state: %w", err)
		}
		if st.State == wantState {
			return nil
		}
		time.Sleep(svcPollInterval)
	}
	return fmt.Errorf("timed out waiting for service to reach state %d", wantState)
}

// ================================
// =========== Commands ===========
// ================================

func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not determine executable path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("could not connect to SCM: %w", err)
	}
	defer m.Disconnect()

	existing, err := m.OpenService(svcName)
	if err == nil {
		existing.Close()
		return fmt.Errorf("service %q already exists", svcName)
	}

	s, err := m.CreateService(svcName, exePath, mgr.Config{
		DisplayName: "KubeArmor Security Service",
		Description: svcDesc,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("could not create service: %w", err)
	}
	defer s.Close()

	if err := eventlog.InstallAsEventCreate(svcName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		kg.Warnf("Failed to register event log source: %v", err)
	}

	fmt.Printf("Service %q installed successfully.\n", svcName)
	return nil
}

func uninstallService() error {
	m, s, err := openSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	// Stop first if running
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("could not query service: %w", err)
	}
	if st.State == svc.Running || st.State == svc.Paused {
		if err := stopService(s); err != nil {
			return fmt.Errorf("could not stop service before uninstall: %w", err)
		}
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("could not delete service: %w", err)
	}
	_ = eventlog.Remove(svcName)

	fmt.Printf("Service %q uninstalled successfully.\n", svcName)
	return nil
}

func startService() error {
	m, s, err := openSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("could not query service: %w", err)
	}
	if st.State == svc.Running {
		fmt.Printf("Service %q is already running.\n", svcName)
		return nil
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("could not start service: %w", err)
	}
	if err := waitForState(s, svc.Running); err != nil {
		return err
	}

	fmt.Printf("Service %q started.\n", svcName)
	return nil
}

// stopService is the shared internal helper used by stopServiceCmd,
// restartService, and uninstallService.
func stopService(s *mgr.Service) error {
	fmt.Println("querying service...")
	st, err := s.Query()
	if err != nil {
		fmt.Printf("error querying service state: %s", err)
		return fmt.Errorf("could not query service state: %w", err)
	}

	switch st.State {
	case svc.Stopped:
		// Nothing to do
		fmt.Println("already stopped...")
		return nil
	case svc.StopPending:
		// Already on the way down — just wait it out
		fmt.Println("already in stopping state...")
		return waitForState(s, svc.Stopped)
	}

	fmt.Println("sending stop signal...")
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("could not send stop control: %w", err)
	}
	return waitForState(s, svc.Stopped)
}

func stopServiceCmd() error {
	fmt.Println("opening SCM...")
	m, s, err := openSCM()
	if err != nil {
		fmt.Printf("error opening SCM: %s", err)
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	fmt.Println("querying service...")
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("could not query service: %w", err)
	}
	if st.State == svc.Stopped {
		fmt.Printf("Service %q is already stopped.\n", svcName)
		return nil
	}
	fmt.Println("stopping service now...")
	if err := stopService(s); err != nil {
		fmt.Printf("error stoping service: %s", err)
		return err
	}

	fmt.Printf("Service %q stopped.\n", svcName)
	return nil
}

func restartService() error {
	m, s, err := openSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("could not query service: %w", err)
	}
	if st.State == svc.Running || st.State == svc.Paused {
		fmt.Printf("Stopping service %q...\n", svcName)
		if err := stopService(s); err != nil {
			return fmt.Errorf("could not stop service: %w", err)
		}
	}

	fmt.Printf("Starting service %q...\n", svcName)
	if err := s.Start(); err != nil {
		return fmt.Errorf("could not start service: %w", err)
	}
	if err := waitForState(s, svc.Running); err != nil {
		return err
	}

	fmt.Printf("Service %q restarted.\n", svcName)
	return nil
}

func statusService() error {
	m, s, err := openSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("could not query service: %w", err)
	}

	stateNames := map[svc.State]string{
		svc.Stopped:         "Stopped",
		svc.StartPending:    "Start Pending",
		svc.StopPending:     "Stop Pending",
		svc.Running:         "Running",
		svc.ContinuePending: "Continue Pending",
		svc.PausePending:    "Pause Pending",
		svc.Paused:          "Paused",
	}
	stateName, ok := stateNames[st.State]
	if !ok {
		stateName = fmt.Sprintf("Unknown (%d)", st.State)
	}

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("could not read service config: %w", err)
	}

	startTypeNames := map[uint32]string{
		mgr.StartAutomatic: "Automatic",
		mgr.StartManual:    "Manual",
		mgr.StartDisabled:  "Disabled",
	}
	startType, ok := startTypeNames[cfg.StartType]
	if !ok {
		startType = fmt.Sprintf("Unknown (%d)", cfg.StartType)
	}

	fmt.Printf("Service:     %s\n", svcName)
	fmt.Printf("Display:     %s\n", cfg.DisplayName)
	fmt.Printf("State:       %s\n", stateName)
	fmt.Printf("Start type:  %s\n", startType)
	fmt.Printf("Binary:      %s\n", cfg.BinaryPathName)
	fmt.Printf("PID:         %d\n", st.ProcessId)

	return nil
}

// ===========================
// ======= Entry point =======
// ===========================

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: kubearmor.exe <command>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  install    Register KubeArmor as a Windows service")
	fmt.Fprintln(os.Stderr, "  uninstall  Stop (if running) and remove the service")
	fmt.Fprintln(os.Stderr, "  start      Start the service")
	fmt.Fprintln(os.Stderr, "  stop       Stop the service")
	fmt.Fprintln(os.Stderr, "  restart    Stop then start the service")
	fmt.Fprintln(os.Stderr, "  status     Print current service state and configuration")
}

func main() {
	if len(os.Args) > 1 {
		var err error
		switch os.Args[1] {
		case "install":
			err = installService()
		case "uninstall":
			err = uninstallService()
		case "start":
			err = startService()
		case "stop":
			fmt.Println("stopping service...")
			err = stopServiceCmd()
		case "restart":
			err = restartService()
		case "status":
			err = statusService()
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %q\n\n", os.Args[1])
			printUsage()
			os.Exit(1)
		}
		if err != nil {
			kg.Errf("%v", err)
			os.Exit(1)
		}
		return
	}

	interactive, err := svc.IsWindowsService()
	if err != nil {
		kg.Errf("Failed to determine session type: %v", err)
		os.Exit(1)
	}

	if !interactive {
		// Running directly from a terminal — foreground mode for debugging
		if err := windowsPreflight(); err != nil {
			kg.Errf("Preflight failed: %v", err)
			os.Exit(1)
		}
		core.KubeArmor()
		return
	}

	// Launched by SCM
	if err := svc.Run(svcName, &kubeArmorService{}); err != nil {
		kg.Errf("Service run failed: %v", err)
		os.Exit(1)
	}
}
