package main

import (
	"encoding/json"
	"io"
	"log"
	"os"
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
}

type Logger struct {
	mu      sync.Mutex
	writer  io.Writer
	console *log.Logger
	color   bool
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
		writer:  w,
		console: log.New(os.Stdout, "", log.LstdFlags),
		color:   stdoutIsTTY(),
	}
}

func (l *Logger) Write(r Result) {
	if r.Timestamp == "" {
		r.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(r)
	if err != nil {
		l.console.Printf("logger marshal error: %v", err)
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.writer.Write(b); err != nil {
		l.console.Printf("logger write error: %v", err)
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
	l.console.Printf("%s %s (%s -> %s) %s", status, r.Check, r.Type, r.Target, r.Detail)
}
