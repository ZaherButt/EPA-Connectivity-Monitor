//go:build !windows

package main

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// runTracert wraps the host's traceroute(8). Used for local testing on macOS/Linux;
// the Windows build uses tracert.exe.
func runTracert(ctx context.Context, target string, maxHops int, timeout time.Duration) ([]string, error) {
	if maxHops == 0 {
		maxHops = 20
	}
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "traceroute", "-n", "-m", strconv.Itoa(maxHops), target)
	out, _ := cmd.CombinedOutput()
	return splitNonEmpty(string(out)), nil
}

func splitNonEmpty(s string) []string {
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
