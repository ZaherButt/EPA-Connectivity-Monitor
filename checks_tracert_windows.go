//go:build windows

package main

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// runTracert wraps Windows tracert.exe (built into the OS, not an external dependency).
// -d  = no DNS reverse lookups (faster)
// -h  = max hops
// -w  = per-hop wait in ms
func runTracert(ctx context.Context, target string, maxHops int, timeout time.Duration) ([]string, error) {
	if maxHops == 0 {
		maxHops = 20
	}
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "tracert", "-d", "-h", strconv.Itoa(maxHops), "-w", "1500", target)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, err
	}
	return splitNonEmpty(string(out)), nil
}

func splitNonEmpty(s string) []string {
	s = strings.ReplaceAll(s, "\r", "")
	in := strings.Split(s, "\n")
	out := make([]string, 0, len(in))
	for _, l := range in {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
