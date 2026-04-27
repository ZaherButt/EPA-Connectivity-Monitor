//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// defaultGateway uses PowerShell's Get-NetRoute to find the active default gateway.
// Falls back to parsing `route print` if PowerShell is unavailable.
func defaultGateway() (string, error) {
	if gw, err := gatewayViaPowerShell(); err == nil && gw != "" {
		return gw, nil
	}
	return gatewayViaRoutePrint()
}

func gatewayViaPowerShell() (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	gw := strings.TrimSpace(string(out))
	if gw == "" {
		return "", fmt.Errorf("no default route found")
	}
	return gw, nil
}

var routeLineRE = regexp.MustCompile(`^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+\S+\s+(\d+)`)

func gatewayViaRoutePrint() (string, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", err
	}
	bestGW := ""
	bestMetric := -1
	for _, line := range strings.Split(string(out), "\n") {
		m := routeLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		gw := m[1]
		metric := 0
		fmt.Sscanf(m[2], "%d", &metric)
		if bestMetric == -1 || metric < bestMetric {
			bestMetric = metric
			bestGW = gw
		}
	}
	if bestGW == "" {
		return "", fmt.Errorf("no default route in route print output")
	}
	return bestGW, nil
}
