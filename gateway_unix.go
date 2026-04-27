//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// defaultGateway is a best-effort implementation for non-Windows builds (used for local testing only).
func defaultGateway() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("route", "-n", "get", "default").Output()
		if err != nil {
			return "", err
		}
		s := bufio.NewScanner(strings.NewReader(string(out)))
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if strings.HasPrefix(line, "gateway:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "gateway:")), nil
			}
		}
		return "", fmt.Errorf("gateway not found")
	case "linux":
		out, err := exec.Command("ip", "route", "show", "default").Output()
		if err != nil {
			return "", err
		}
		fields := strings.Fields(string(out))
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
		return "", fmt.Errorf("gateway not found")
	}
	return "", fmt.Errorf("default gateway lookup not supported on %s", runtime.GOOS)
}
