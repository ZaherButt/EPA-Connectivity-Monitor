package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// splitTargetHostPort normalizes a target string that may include an embedded
// ":port" suffix (e.g. "host.example.com:443"). Returns the bare host and the
// effective port, with defaultPort used when no port is embedded. Defensive
// against config entries copied verbatim from "host:port"-style log lines —
// without this, net.JoinHostPort(target, port) would produce "host:443:443"
// and the resolver would fail with "no such host".
func splitTargetHostPort(target string, defaultPort int) (string, int) {
	if h, p, err := net.SplitHostPort(target); err == nil {
		port := defaultPort
		if pn, perr := strconv.Atoi(p); perr == nil && pn > 0 {
			port = pn
		}
		return h, port
	}
	return target, defaultPort
}

func runCheck(ctx context.Context, c CheckConfig, pingCount int) Result {
	res := Result{
		Check:  c.Name,
		Type:   c.Type,
		Target: c.Target,
		Tags:   c.Tags,
	}
	switch c.Type {
	case "gateway_ping":
		gw, err := defaultGateway()
		if err != nil {
			res.Error = fmt.Sprintf("gateway lookup: %v", err)
			return res
		}
		res.Target = gw
		fillPing(&res, gw, c.Timeout, pingCount)
	case "internet_ping":
		fillPing(&res, c.Target, c.Timeout, pingCount)
	case "tcp443":
		fillTCP(&res, c.Target, 443, c.Timeout)
	case "dns_a":
		res.Resolver = c.Resolver
		fillDNS(&res, c.Target, c.Resolver, c.Timeout)
	case "tls":
		fillTLS(&res, c)
	case "tls_resume":
		fillTLSResume(&res, c)
	case "holdopen":
		fillHoldOpen(ctx, &res, c)
	case "host_health":
		fillHostHealth(&res)
	case "log_tail":
		fillLogTail(&res, c)
	case "proxy_detect":
		fillProxyDetect(&res, c)
	case "service_status":
		fillServiceStatus(&res, c)
	default:
		res.Error = "unknown check type"
	}

	if !res.Success && c.TraceOnFailure {
		traceTarget := res.Target
		if c.Type == "dns_a" {
			traceTarget = c.Resolver
		}
		if traceTarget != "" {
			hops, err := runTracert(ctx, traceTarget, c.MaxHops, 60*time.Second)
			if res.Extra == nil {
				res.Extra = map[string]any{}
			}
			if err != nil {
				res.Extra["tracert_error"] = err.Error()
			} else {
				res.Extra["tracert_target"] = traceTarget
				res.Extra["tracert"] = hops
			}
		}
	}
	return res
}

// msFloat converts a time.Duration to milliseconds as float64.
func msFloat(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// icmpDisabled is set sticky-true the first time ICMP fails with a privilege
// error. After that, fillPing returns immediately with a "skipped" result so
// we don't pollute the log with a continuous failure stream when the binary
// is being run from a non-elevated cmd window. The warning line is emitted
// exactly once, on the first detection.
var (
	icmpDisabled atomic.Bool
	icmpWarnOnce sync.Once
)

func isPermissionError(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "permission denied") ||
		strings.Contains(s, "operation not permitted") ||
		strings.Contains(s, "access permissions") ||
		strings.Contains(s, "10013") ||
		strings.Contains(s, "forbidden") ||
		strings.Contains(s, "not permitted")
}

func markICMPDisabledOnce(reason string) {
	icmpDisabled.Store(true)
	icmpWarnOnce.Do(func() {
		fmt.Fprintf(os.Stderr,
			"WARN: ICMP unavailable (%s). gateway_ping/internet_ping checks will "+
				"be reported as 'skipped' in the log instead of 'failed'. To enable "+
				"ICMP, run elevated (right-click cmd -> 'Run as Administrator') or "+
				"install as a Windows service (epa-connectivity-monitor.exe -install) "+
				"which runs as LocalSystem.\n", reason)
	})
}

func fillPingSkipped(res *Result, target string) {
	res.Target = target
	res.Success = true
	res.Detail = "ICMP skipped: process not elevated, raw sockets unavailable"
	res.Extra = map[string]any{
		"skipped":        true,
		"skipped_reason": "icmp_no_admin",
	}
}

func fillPing(res *Result, target string, timeout time.Duration, count int) {
	if icmpDisabled.Load() {
		fillPingSkipped(res, target)
		return
	}
	pinger, err := probing.NewPinger(target)
	if err != nil {
		res.Error = fmt.Sprintf("new pinger: %v", err)
		if isPermissionError(err.Error()) {
			markICMPDisabledOnce(err.Error())
			fillPingSkipped(res, target)
		}
		return
	}
	// On Windows, ICMP requires privileged (raw socket) mode and admin rights.
	if runtime.GOOS == "windows" {
		pinger.SetPrivileged(true)
	}
	pinger.Count = count
	pinger.Timeout = timeout
	pinger.Interval = 200 * time.Millisecond
	if err := pinger.Run(); err != nil {
		if isPermissionError(err.Error()) {
			markICMPDisabledOnce(err.Error())
			fillPingSkipped(res, target)
			return
		}
		res.Error = fmt.Sprintf("ping run: %v", err)
		return
	}
	stats := pinger.Statistics()
	res.PacketLoss = stats.PacketLoss
	if stats.PacketsRecv > 0 {
		res.LatencyMs = float64(stats.AvgRtt) / float64(time.Millisecond)
		res.Success = stats.PacketLoss < 100
		res.Detail = fmt.Sprintf("sent=%d recv=%d loss=%.0f%% avg=%.2fms",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss, res.LatencyMs)
	} else {
		res.Success = false
		res.Detail = fmt.Sprintf("sent=%d recv=0 loss=100%%", stats.PacketsSent)
		if res.Error == "" {
			res.Error = "no ICMP replies"
		}
	}
}

func fillTCP(res *Result, host string, port int, timeout time.Duration) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	elapsed := time.Since(start)
	res.LatencyMs = float64(elapsed) / float64(time.Millisecond)
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		res.Detail = fmt.Sprintf("dial %s failed in %.2fms", addr, res.LatencyMs)
		return
	}
	_ = conn.Close()
	res.Success = true
	res.Detail = fmt.Sprintf("connected %s in %.2fms", addr, res.LatencyMs)
}

// fillDNS sends an A-record lookup for `name` directly to the specified resolver IP
// (UDP port 53). Bypasses the OS resolver so the configured server is actually used.
func fillDNS(res *Result, name, resolver string, timeout time.Duration) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(resolver, "53"))
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	ips, err := r.LookupIP(ctx, "ip4", name)
	elapsed := time.Since(start)
	res.LatencyMs = float64(elapsed) / float64(time.Millisecond)
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		res.Detail = fmt.Sprintf("A %s @%s failed in %.2fms", name, resolver, res.LatencyMs)
		return
	}
	if len(ips) == 0 {
		res.Success = false
		res.Error = "no A records returned"
		res.Detail = fmt.Sprintf("A %s @%s returned 0 records", name, resolver)
		return
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	res.Success = true
	res.Detail = fmt.Sprintf("A %s @%s -> %d records [%s] in %.2fms",
		name, resolver, len(ips), strings.Join(addrs, ", "), res.LatencyMs)
}
