//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryEx = kernel32.NewProc("GlobalMemoryStatusEx")

	cpuMu      sync.Mutex
	lastIdle   uint64
	lastKernel uint64
	lastUser   uint64
	lastSample time.Time

	tcpStatsMu sync.Mutex
	lastTCP    *tcpStatsSnap
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type tcpStatsSnap struct {
	when            time.Time
	segmentsRetrans int64
	resetsSent      int64
	resetsRecv      int64
}

func fillHostHealth(res *Result) {
	res.Success = true
	extra := map[string]any{
		"goroutines": runtime.NumGoroutine(),
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	extra["self_alloc_mb"] = round1(float64(ms.Alloc) / 1024 / 1024)

	if cpu, err := cpuPercent(); err == nil {
		extra["cpu_pct_total"] = round1(cpu)
	}
	if free, total, err := memMB(); err == nil {
		extra["mem_free_mb"] = round1(free)
		extra["mem_total_mb"] = round1(total)
	}
	if est, err := tcpEstablishedCount(); err == nil {
		extra["tcp_established"] = est
	}
	if cur, err := readTCPStats(); err == nil {
		tcpStatsMu.Lock()
		if lastTCP != nil {
			dt := cur.when.Sub(lastTCP.when).Seconds()
			if dt > 0 {
				extra["tcp_retrans_per_sec"] = round1(float64(cur.segmentsRetrans-lastTCP.segmentsRetrans) / dt)
				extra["tcp_resets_sent_per_sec"] = round1(float64(cur.resetsSent-lastTCP.resetsSent) / dt)
				extra["tcp_resets_recv_per_sec"] = round1(float64(cur.resetsRecv-lastTCP.resetsRecv) / dt)
			}
		}
		lastTCP = cur
		tcpStatsMu.Unlock()
	}

	cpu, _ := extra["cpu_pct_total"].(float64)
	mfree, _ := extra["mem_free_mb"].(float64)
	res.Detail = fmt.Sprintf("cpu=%.1f%% memfree=%.0fMB tcp_est=%v retrans/s=%v",
		cpu, mfree, extra["tcp_established"], extra["tcp_retrans_per_sec"])
	res.Extra = extra
}

func systemTimes() (idle, kernel, user uint64, err error) {
	var i, k, u windows.Filetime
	r1, _, e1 := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&i)),
		uintptr(unsafe.Pointer(&k)),
		uintptr(unsafe.Pointer(&u)),
	)
	if r1 == 0 {
		return 0, 0, 0, e1
	}
	return ftToU64(i), ftToU64(k), ftToU64(u), nil
}

func ftToU64(f windows.Filetime) uint64 {
	return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)
}

func cpuPercent() (float64, error) {
	idle, kern, user, err := systemTimes()
	if err != nil {
		return 0, err
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	now := time.Now()
	if lastSample.IsZero() {
		lastIdle, lastKernel, lastUser, lastSample = idle, kern, user, now
		return 0, nil
	}
	dIdle := idle - lastIdle
	dKern := kern - lastKernel
	dUser := user - lastUser
	lastIdle, lastKernel, lastUser, lastSample = idle, kern, user, now
	total := dKern + dUser
	if total == 0 {
		return 0, nil
	}
	busy := total - dIdle
	return float64(busy) * 100.0 / float64(total), nil
}

func memMB() (free, total float64, err error) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r1, _, e1 := procGlobalMemoryEx.Call(uintptr(unsafe.Pointer(&m)))
	if r1 == 0 {
		return 0, 0, e1
	}
	return float64(m.AvailPhys) / 1024 / 1024, float64(m.TotalPhys) / 1024 / 1024, nil
}

func tcpEstablishedCount() (int, error) {
	out, err := exec.Command("netstat", "-an", "-p", "tcp").Output()
	if err != nil {
		return 0, err
	}
	return strings.Count(string(out), "ESTABLISHED"), nil
}

func readTCPStats() (*tcpStatsSnap, error) {
	out, err := exec.Command("netstat", "-s", "-p", "tcp").Output()
	if err != nil {
		return nil, err
	}
	s := string(out)
	return &tcpStatsSnap{
		when:            time.Now(),
		segmentsRetrans: extractInt(s, `(?i)Segments\s+Retransmitted\s*=\s*(\d+)`),
		resetsSent:      extractInt(s, `(?i)Resets\s+Sent\s*=\s*(\d+)`),
		resetsRecv:      extractInt(s, `(?i)Resets\s+Received\s*=\s*(\d+)`),
	}, nil
}

func extractInt(s, pat string) int64 {
	re := regexp.MustCompile(pat)
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return 0
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	return n
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}
