package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// runSnapshot implements the `--snapshot` mode: every configured check is
// executed exactly once in parallel and the results are printed to stdout as
// a colour-coded PASS/FAIL table. No log file is written. Exit code is 0 if
// every check passes, 1 if any failed.
//
// Intended for engineers who want a quick "is this box healthy right now?"
// answer before installing the service or while remoted into a customer
// connector. NOT a substitute for continuous monitoring — many of the
// problems this tool exists to catch (intermittent latency spikes, hold-open
// resets, asymmetric path failures) only show up over time.
func runSnapshot(cfg *Config) int {
	color := stdoutIsTTY()

	if connectorTenantID != "" {
		fmt.Printf("Tenant ID    : %s\n", connectorTenantID)
		fmt.Printf("Source       : %s\n", tenantIDSource)
		fmt.Println()
	}

	fmt.Printf("Running %d checks once...\n\n", len(cfg.Checks))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results := make([]Result, len(cfg.Checks))
	var wg sync.WaitGroup
	for i, c := range cfg.Checks {
		wg.Add(1)
		go func(i int, c CheckConfig) {
			defer wg.Done()
			start := time.Now()
			r := runCheck(ctx, c, cfg.PingCount)
			if r.Timestamp == "" {
				r.Timestamp = start.UTC().Format(time.RFC3339)
			}
			results[i] = r
		}(i, c)
	}
	wg.Wait()

	sort.SliceStable(results, func(a, b int) bool {
		if results[a].Success != results[b].Success {
			return !results[a].Success
		}
		return results[a].Check < results[b].Check
	})

	const (
		green = "\x1b[32m"
		red   = "\x1b[31m"
		dim   = "\x1b[2m"
		bold  = "\x1b[1m"
		reset = "\x1b[0m"
	)
	colorize := func(s, code string) string {
		if !color {
			return s
		}
		return code + s + reset
	}

	maxName := len("CHECK")
	maxType := len("TYPE")
	maxTarget := len("TARGET")
	for _, r := range results {
		if len(r.Check) > maxName {
			maxName = len(r.Check)
		}
		if len(r.Type) > maxType {
			maxType = len(r.Type)
		}
		if len(r.Target) > maxTarget {
			maxTarget = len(r.Target)
		}
	}
	if maxTarget > 40 {
		maxTarget = 40
	}

	header := fmt.Sprintf("%-7s %-*s %-*s %-*s %s",
		"STATUS", maxName, "CHECK", maxType, "TYPE", maxTarget, "TARGET", "DETAIL")
	fmt.Println(colorize(header, bold))
	fmt.Println(strings.Repeat("-", len(header)))

	failed := 0
	for _, r := range results {
		status := "PASS"
		statusColored := colorize(status, green)
		if !r.Success {
			status = "FAIL"
			statusColored = colorize(status, red)
			failed++
		}
		target := r.Target
		if len(target) > maxTarget {
			target = target[:maxTarget-1] + "…"
		}
		detail := r.Detail
		if detail == "" && r.Error != "" {
			detail = "ERROR: " + r.Error
		}
		if !r.Success && color {
			detail = colorize(detail, dim)
		}
		fmt.Printf("%s   %-*s %-*s %-*s %s\n",
			statusColored, maxName, r.Check, maxType, r.Type, maxTarget, target, detail)
	}

	fmt.Println()
	summary := fmt.Sprintf("Summary: %d/%d passed", len(results)-failed, len(results))
	if failed == 0 {
		fmt.Println(colorize(summary, green))
		return 0
	}
	fmt.Fprintln(os.Stderr, colorize(summary+" — see FAIL lines above", red))
	return 1
}
