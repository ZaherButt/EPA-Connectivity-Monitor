//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "EpaConnectivityMonitor"
const serviceDisplay = "EPA Connectivity Monitor"
const serviceDesc = "Polls network endpoints (gateway ping, ICMP, DNS, TCP/443) and writes JSON-Lines log."

// runService is the SCM-side entrypoint. Returns true if we're running as a service
// (in which case SCM dispatch handles the lifecycle), false if running interactively.
func runService(cfg *Config, devMode bool) (handled bool, err error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf("svc.IsWindowsService: %w", err)
	}
	if !isSvc {
		return false, nil
	}
	elog, _ := eventlog.Open(serviceName)
	if elog != nil {
		defer elog.Close()
	}
	h := &serviceHandler{cfg: cfg, devMode: devMode, elog: elog}
	if err := svc.Run(serviceName, h); err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("svc.Run failed: %v", err))
		}
		return true, err
	}
	return true, nil
}

type serviceHandler struct {
	cfg     *Config
	devMode bool
	elog    *eventlog.Log
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (ssec bool, errno uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	logger := NewLogger(h.cfg)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, c := range h.cfg.Checks {
		wg.Add(1)
		go func(c CheckConfig) {
			defer wg.Done()
			runLoop(ctx, c, h.cfg.PingCount, logger, false)
		}(c)
	}

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	if h.elog != nil {
		h.elog.Info(1, fmt.Sprintf("%s started (checks=%d, dev=%v)", serviceName, len(h.cfg.Checks), h.devMode))
	}

loop:
	for {
		req := <-r
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			break loop
		}
	}

	status <- svc.Status{State: svc.StopPending}
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	if h.elog != nil {
		h.elog.Info(1, fmt.Sprintf("%s stopped", serviceName))
	}
	status <- svc.Status{State: svc.Stopped}
	return false, 0
}

// installService registers the service with SCM and starts it.
// configPath must already be absolute and accessible by LocalSystem.
func installService(configPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate exe: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("mgr.Connect: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already installed; use --uninstall first", serviceName)
	}

	cfg := mgr.Config{
		DisplayName:      serviceDisplay,
		Description:      serviceDesc,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "", // empty = LocalSystem
	}
	s, err := m.CreateService(serviceName, exe, cfg, "--config", configPath)
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer s.Close()

	// Best-effort: register with the event log; ignore "already exists".
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	if err := s.Start(); err != nil {
		return fmt.Errorf("service installed but failed to start: %w", err)
	}
	return nil
}

// uninstallService stops (best effort) and removes the service.
func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("mgr.Connect: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q not installed", serviceName)
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		// Not fatal: service may already be stopped.
		_ = err
	}
	// Wait briefly for stop.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil || st.State == svc.Stopped {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	_ = eventlog.Remove(serviceName)
	return nil
}
