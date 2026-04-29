package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

type Result struct {
	Timestamp  string         `json:"timestamp"`
	Check      string         `json:"check"`
	Type       string         `json:"type"`
	Target     string         `json:"target"`
	Resolver   string         `json:"resolver,omitempty"`
	Success    bool           `json:"success"`
	LatencyMs  float64        `json:"latency_ms,omitempty"`
	PacketLoss float64        `json:"packet_loss_pct,omitempty"`
	Detail     string         `json:"detail,omitempty"`
	Error      string         `json:"error,omitempty"`
	Extra      map[string]any `json:"extra,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
}

type Logger struct {
	mu          sync.Mutex
	writer      io.Writer
	console     *log.Logger
	color       bool
	logPath     string
	minFreeMB   uint64
	lastCheck   time.Time
	diskFull    bool
	lastWarnAt  time.Time
	tenantID    string
}

const (
	ansiReset = "\x1b[0m"
	ansiGreen = "\x1b[32m"
	ansiRed   = "\x1b[31m"
)

func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func NewLogger(cfg *Config) *Logger {
	w := &lumberjack.Logger{
		Filename:   cfg.LogFile,
		MaxSize:    cfg.LogMaxSizeMB,
		MaxBackups: cfg.LogMaxBackups,
		MaxAge:     cfg.LogMaxAgeDays,
		Compress:   true,
	}
	return &Logger{
		writer:      w,
		console:     log.New(os.Stdout, "", log.LstdFlags),
		color:       stdoutIsTTY(),
		logPath:     cfg.LogFile,
		minFreeMB:   uint64(cfg.LogMinFreeDiskMB),
		tenantID:    connectorTenantID,
	}
}

// diskHasRoom returns true if the log volume has at least minFreeMB free.
// Result is cached for 30s to keep the hot path cheap. On stat error we fail
// open (allow writes) rather than silencing the tool on a transient hiccup.
func (l *Logger) diskHasRoom() bool {
	if l.minFreeMB == 0 {
		return true
	}
	now := time.Now()
	if now.Sub(l.lastCheck) < 30*time.Second {
		return !l.diskFull
	}
	l.lastCheck = now
	dir := filepath.Dir(l.logPath)
	if dir == "" {
		dir = "."
	}
	free, err := freeDiskMB(dir)
	if err != nil {
		l.diskFull = false
		return true
	}
	full := free < l.minFreeMB
	if full && !l.diskFull {
		l.console.Printf("WARN: log volume %s has %d MB free (< %d MB threshold) — pausing log writes to protect disk",
			dir, free, l.minFreeMB)
		l.lastWarnAt = now
	} else if !full && l.diskFull {
		l.console.Printf("INFO: log volume %s has %d MB free again — resuming log writes", dir, free)
	}
	l.diskFull = full
	return !full
}

func (l *Logger) Write(r Result) {
	if r.Timestamp == "" {
		r.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if l.tenantID != "" {
		if r.Extra == nil {
			r.Extra = map[string]any{}
		}
		r.Extra["tenant_id"] = l.tenantID
	}
	b, err := json.Marshal(r)
	if err != nil {
		l.console.Printf("logger marshal error: %v", err)
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.diskHasRoom() {
		if _, err := l.writer.Write(b); err != nil {
			l.console.Printf("logger write error: %v", err)
		}
	}
	status := "[OK]"
	if !r.Success {
		status = "[FAIL]"
	}
	if l.color {
		if r.Success {
			status = ansiGreen + status + ansiReset
		} else {
			status = ansiRed + status + ansiReset
		}
	}
	tagSuffix := ""
	if len(r.Tags) > 0 {
		tagSuffix = " [" + strings.Join(r.Tags, " ") + "]"
	}
	l.console.Printf("%s %s (%s -> %s) %s%s", status, r.Check, r.Type, r.Target, r.Detail, tagSuffix)
}
