package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// exeDir returns the directory containing the running executable.
// Falls back to "." if it can't be determined.
func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err == nil {
		p = resolved
	}
	return filepath.Dir(p)
}

type Config struct {
	LogFile          string        `yaml:"log_file"`
	LogMaxSizeMB     int           `yaml:"log_max_size_mb"`
	LogMaxBackups    int           `yaml:"log_max_backups"`
	LogMaxAgeDays    int           `yaml:"log_max_age_days"`
	LogMinFreeDiskMB int           `yaml:"log_min_free_disk_mb"`
	DefaultInterval  time.Duration `yaml:"default_interval"`
	DefaultTimeout   time.Duration `yaml:"default_timeout"`
	PingCount        int           `yaml:"ping_count"`
	Checks           []CheckConfig `yaml:"checks"`
}

type CheckConfig struct {
	Name     string        `yaml:"name"`
	Type     string        `yaml:"type"`     // see validateType for full list
	Target   string        `yaml:"target"`   // host/IP for ping/tcp/tls; hostname for dns_a
	Resolver string        `yaml:"resolver"` // dns_a only: resolver IP (e.g. "1.1.1.1")
	Interval time.Duration `yaml:"interval"` // optional; falls back to default
	Timeout  time.Duration `yaml:"timeout"`  // optional; falls back to default

	// Optional, type-specific
	Port           int           `yaml:"port"`             // tls/holdopen (default 443)
	TLSServerName  string        `yaml:"tls_server_name"`  // tls/holdopen SNI override
	HoldFor        time.Duration `yaml:"hold_for"`         // holdopen: duration to hold connection (default 4m)
	TCPKeepalive   bool          `yaml:"tcp_keepalive"`    // holdopen: enable OS-level TCP keepalives (default false)
	TraceOnFailure bool          `yaml:"trace_on_failure"` // any check: run tracert on failure
	MaxHops        int           `yaml:"max_hops"`         // tracert max hops (default 20)
	LogPath        string        `yaml:"log_path"`         // log_tail: file path
	Pattern        string        `yaml:"pattern"`          // log_tail: regex (default "(?i)error|warn|fail")

	// Free-form labels for grouping/filtering downstream (e.g. region:eu, role:signaling,
	// cluster:eur1, provider:azure-sb). No semantic meaning to the runner — purely metadata
	// passed through to the JSON log and the console line.
	Tags []string `yaml:"tags"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.LogFile == "" {
		c.LogFile = filepath.Join(exeDir(), "epa-connectivity-monitor.log")
	} else if !filepath.IsAbs(c.LogFile) {
		c.LogFile = filepath.Join(exeDir(), c.LogFile)
	}
	if dir := filepath.Dir(c.LogFile); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create log dir %s: %w", dir, err)
		}
	}
	if c.LogMaxSizeMB == 0 {
		c.LogMaxSizeMB = 500
	}
	if c.LogMaxBackups == 0 {
		c.LogMaxBackups = 9
	}
	if c.LogMaxAgeDays == 0 {
		c.LogMaxAgeDays = 7
	}
	if c.LogMinFreeDiskMB == 0 {
		c.LogMinFreeDiskMB = 5120
	}
	if c.DefaultInterval == 0 {
		c.DefaultInterval = 60 * time.Second
	}
	if c.DefaultTimeout == 0 {
		c.DefaultTimeout = 5 * time.Second
	}
	if c.PingCount == 0 {
		c.PingCount = 3
	}
	for i := range c.Checks {
		if c.Checks[i].Interval == 0 {
			c.Checks[i].Interval = c.DefaultInterval
		}
		if c.Checks[i].Timeout == 0 {
			c.Checks[i].Timeout = c.DefaultTimeout
		}
		switch c.Checks[i].Type {
		case "gateway_ping", "internet_ping", "tcp443", "dns_a",
			"tls", "tls_resume", "holdopen", "host_health", "log_tail":
		default:
			return nil, fmt.Errorf("check %q: unknown type %q", c.Checks[i].Name, c.Checks[i].Type)
		}
		needsTarget := c.Checks[i].Type != "gateway_ping" && c.Checks[i].Type != "host_health" && c.Checks[i].Type != "log_tail"
		if needsTarget && c.Checks[i].Target == "" {
			return nil, fmt.Errorf("check %q: target is required for type %s", c.Checks[i].Name, c.Checks[i].Type)
		}
		if c.Checks[i].Type == "dns_a" && c.Checks[i].Resolver == "" {
			return nil, fmt.Errorf("check %q: resolver is required for type dns_a", c.Checks[i].Name)
		}
		if c.Checks[i].Type == "log_tail" && c.Checks[i].LogPath == "" {
			return nil, fmt.Errorf("check %q: log_path is required for type log_tail", c.Checks[i].Name)
		}
		if c.Checks[i].Type == "holdopen" && c.Checks[i].HoldFor == 0 {
			c.Checks[i].HoldFor = 4 * time.Minute
		}
		if c.Checks[i].Name == "" {
			c.Checks[i].Name = fmt.Sprintf("%s:%s", c.Checks[i].Type, c.Checks[i].Target)
		}
	}
	if len(c.Checks) == 0 {
		return nil, fmt.Errorf("no checks defined in config")
	}
	return c, nil
}
