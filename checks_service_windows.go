//go:build windows

package main

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// fillServiceStatus queries the Windows Service Control Manager for the named
// service and reports its current state. Use c.Target as the service name —
// e.g. "WAPCSvc" for the EPA connector, or "WAPCUpdater" for its updater.
//
// Success criteria: the service exists AND is in the Running state. Anything
// else (Stopped, StartPending, ContinuePending, PausePending, Paused,
// StopPending) is reported as failure with the actual state in the detail.
//
// We also surface the configured start type (Auto/Manual/Disabled), the
// process exit code from the last termination if any, and (for Auto-start
// services) the time elapsed since process start when running. This catches
// the "service died at 03:00 and SCM hasn't restarted it yet" class of
// problem.
func fillServiceStatus(res *Result, c CheckConfig) {
	if c.Target == "" {
		res.Success = false
		res.Error = "service_status: target (service name) is required"
		return
	}
	m, err := mgr.Connect()
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("connect SCM: %v", err)
		return
	}
	defer m.Disconnect()

	s, err := m.OpenService(c.Target)
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("open service %q: %v", c.Target, err)
		res.Detail = fmt.Sprintf("service %q not installed or inaccessible", c.Target)
		return
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		res.Success = false
		res.Error = fmt.Sprintf("query service %q: %v", c.Target, err)
		return
	}
	cfg, cfgErr := s.Config()

	stateStr := serviceStateString(st.State)
	startTypeStr := "?"
	if cfgErr == nil {
		startTypeStr = serviceStartTypeString(cfg.StartType)
	}

	res.Extra = map[string]any{
		"service_name": c.Target,
		"state":        stateStr,
		"state_code":   uint32(st.State),
		"start_type":   startTypeStr,
		"win32_exit":   st.Win32ExitCode,
		"service_exit": st.ServiceSpecificExitCode,
		"checkpoint":   st.CheckPoint,
		"wait_hint_ms": st.WaitHint,
	}
	if cfgErr == nil {
		res.Extra["display_name"] = cfg.DisplayName
		res.Extra["binary_path"] = cfg.BinaryPathName
		if cfg.ServiceStartName != "" {
			res.Extra["run_as"] = cfg.ServiceStartName
		}
	}

	if st.State == svc.Running && st.ProcessId != 0 {
		if uptime, err := processUptime(st.ProcessId); err == nil {
			res.Extra["pid"] = st.ProcessId
			res.Extra["uptime_seconds"] = int64(uptime / time.Second)
			res.Extra["started_at"] = time.Now().Add(-uptime).UTC().Format(time.RFC3339)
		}
	}

	if st.State == svc.Running {
		res.Success = true
		detail := fmt.Sprintf("service %q running (start_type=%s)", c.Target, startTypeStr)
		if u, ok := res.Extra["uptime_seconds"].(int64); ok {
			detail += fmt.Sprintf(", uptime=%s", time.Duration(u)*time.Second)
		}
		res.Detail = detail
		return
	}

	res.Success = false
	parts := []string{fmt.Sprintf("state=%s", stateStr)}
	if startTypeStr != "?" {
		parts = append(parts, "start_type="+startTypeStr)
	}
	if st.Win32ExitCode != 0 && st.Win32ExitCode != 1077 {
		parts = append(parts, fmt.Sprintf("win32_exit=%d", st.Win32ExitCode))
	}
	res.Detail = fmt.Sprintf("service %q not running: %s", c.Target, strings.Join(parts, ", "))
	if st.Win32ExitCode != 0 && st.Win32ExitCode != 1077 {
		res.Error = fmt.Sprintf("last exit code %d", st.Win32ExitCode)
	}
}

func serviceStateString(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "Stopped"
	case svc.StartPending:
		return "StartPending"
	case svc.StopPending:
		return "StopPending"
	case svc.Running:
		return "Running"
	case svc.ContinuePending:
		return "ContinuePending"
	case svc.PausePending:
		return "PausePending"
	case svc.Paused:
		return "Paused"
	default:
		return fmt.Sprintf("Unknown(%d)", uint32(s))
	}
}

func serviceStartTypeString(t uint32) string {
	switch t {
	case mgr.StartManual:
		return "Manual"
	case mgr.StartAutomatic:
		return "Automatic"
	case mgr.StartDisabled:
		return "Disabled"
	case 0: // SERVICE_BOOT_START
		return "Boot"
	case 1: // SERVICE_SYSTEM_START
		return "System"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// processUptime opens the target process and returns time since its creation.
// Used to surface "service has restarted N times today" / "service just came
// up 12 seconds ago" signals in the log without needing event-log parsing.
func processUptime(pid uint32) (time.Duration, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	created := time.Unix(0, creation.Nanoseconds())
	return time.Since(created), nil
}
