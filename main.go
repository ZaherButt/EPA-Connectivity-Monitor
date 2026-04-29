package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	flagConfig    = flag.String("config", "config.yaml", "Path to YAML config file")
	flagOnce      = flag.Bool("once", false, "Run each check exactly once and exit")
	flagPrint     = flag.Bool("print-config", false, "Print the loaded config and exit")
	flagDev       = flag.Bool("dev", false, "Dev mode: override all check intervals to 1s (high log volume)")
	flagInstall   = flag.Bool("install", false, "Windows: install as a service (requires --config; runs as LocalSystem)")
	flagUninstall = flag.Bool("uninstall", false, "Windows: stop and remove the installed service")
	flagVersion   = flag.Bool("version", false, "Print version and exit")
)

const (
	version    = "0.4.1"
	bannerLine = "EPA Connectivity Monitor v" + version + " - community diagnostic tool, not a Microsoft product. No warranty. See DISCLAIMER.md."
)

func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Println(bannerLine)
		return
	}

	if *flagUninstall {
		if err := uninstallService(); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("service uninstalled")
		return
	}

	if *flagInstall {
		abs, err := filepath.Abs(*flagConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "resolve config path: %v\n", err)
			os.Exit(1)
		}
		if _, err := os.Stat(abs); err != nil {
			fmt.Fprintf(os.Stderr, "config file not found: %s\n", abs)
			os.Exit(1)
		}
		if err := installService(abs); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("service installed and started")
		return
	}

	cfg, err := LoadConfig(*flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}
	if *flagPrint {
		fmt.Printf("%+v\n", cfg)
		return
	}

	// Print disclaimer banner once at startup (interactive runs only; the SCM
	// service path emits this via the runtime logger instead — see runService).
	fmt.Fprintln(os.Stderr, bannerLine)

	if *flagDev {
		fmt.Fprintln(os.Stderr, "*** DEV MODE: intervals -> 1s, holdopen hold_for -> 5s ***")
		for i := range cfg.Checks {
			cfg.Checks[i].Interval = time.Second
			if cfg.Checks[i].Type == "holdopen" {
				cfg.Checks[i].HoldFor = 5 * time.Second
				cfg.Checks[i].Interval = 7 * time.Second
			}
		}
		ext := filepath.Ext(cfg.LogFile)
		base := strings.TrimSuffix(cfg.LogFile, ext)
		cfg.LogFile = base + "-dev" + ext
		fmt.Fprintf(os.Stderr, "*** DEV MODE: log file -> %s ***\n", cfg.LogFile)
	}

	// If launched by SCM, hand control to the service runner and exit when SCM stops us.
	if handled, err := runService(cfg, *flagDev); handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "service runtime error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	runInteractive(cfg)
}

func runInteractive(cfg *Config) {
	logger := NewLogger(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "shutdown signal received")
		cancel()
	}()

	var wg sync.WaitGroup
	for _, c := range cfg.Checks {
		wg.Add(1)
		go func(c CheckConfig) {
			defer wg.Done()
			runLoop(ctx, c, cfg.PingCount, logger, *flagOnce)
		}(c)
	}
	wg.Wait()
}

func runLoop(ctx context.Context, c CheckConfig, pingCount int, logger *Logger, once bool) {
	exec := func() {
		res := runCheck(ctx, c, pingCount)
		logger.Write(res)
	}
	exec()
	if once {
		return
	}
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			exec()
		}
	}
}
