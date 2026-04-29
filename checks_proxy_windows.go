//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// fillProxyDetect inspects all the well-known places a Windows host might be
// configured to use an HTTP/HTTPS proxy, plus WPAD DNS auto-discovery. It
// generates no outbound traffic apart from one DNS query for "wpad".
//
// Sources:
//   - HTTP_PROXY / HTTPS_PROXY / NO_PROXY environment variables
//   - WinHTTP system proxy (via `netsh winhttp show proxy`)
//   - WinINET per-machine proxy (HKLM\...\Internet Settings)
//   - WinINET per-user proxy (HKCU\...\Internet Settings) — when running as
//     LocalSystem this is the SYSTEM account's profile, not the logged-in user
//   - WPAD DNS auto-discovery (does the name "wpad" resolve?)
//
// All findings are read-only. No registry writes, no traffic to the proxy.
func fillProxyDetect(res *Result, c CheckConfig) {
	extra := map[string]any{}
	findings := []string{}

	envHTTP := os.Getenv("HTTP_PROXY")
	envHTTPS := os.Getenv("HTTPS_PROXY")
	envNo := os.Getenv("NO_PROXY")
	extra["env_http_proxy"] = envHTTP
	extra["env_https_proxy"] = envHTTPS
	extra["env_no_proxy"] = envNo
	if envHTTP != "" || envHTTPS != "" {
		findings = append(findings, "env_proxy")
	}

	winhttpProxy, winhttpBypass, winhttpErr := readWinHTTPProxy()
	extra["winhttp_proxy"] = winhttpProxy
	extra["winhttp_bypass"] = winhttpBypass
	if winhttpErr != "" {
		extra["winhttp_error"] = winhttpErr
	}
	if winhttpProxy != "" && !strings.EqualFold(winhttpProxy, "(none)") &&
		!strings.EqualFold(winhttpProxy, "direct access (no proxy server)") {
		findings = append(findings, "winhttp")
	}

	hklmProxy, hklmAutoCfg := readInternetSettings(registry.LOCAL_MACHINE)
	hkcuProxy, hkcuAutoCfg := readInternetSettings(registry.CURRENT_USER)
	extra["wininet_hklm_proxy"] = hklmProxy
	extra["wininet_hklm_autoconfig_url"] = hklmAutoCfg
	extra["wininet_hkcu_proxy"] = hkcuProxy
	extra["wininet_hkcu_autoconfig_url"] = hkcuAutoCfg
	if hklmProxy != "" || hkcuProxy != "" {
		findings = append(findings, "wininet")
	}
	if hklmAutoCfg != "" || hkcuAutoCfg != "" {
		findings = append(findings, "pac_url")
	}

	wpadResolves, wpadTarget := wpadDNSResolves()
	extra["wpad_dns_resolves"] = wpadResolves
	extra["wpad_dns_target"] = wpadTarget
	if wpadResolves {
		findings = append(findings, "wpad")
	}

	extra["any_proxy_configured"] = len(findings) > 0
	extra["findings"] = findings

	res.Success = true
	if len(findings) == 0 {
		res.Detail = "no proxy detected (env, WinHTTP, WinINET HKLM/HKCU, WPAD all clean)"
	} else {
		res.Detail = fmt.Sprintf("proxy indicators detected: %s", strings.Join(findings, ","))
	}
	res.Extra = extra
}

func readWinHTTPProxy() (proxy, bypass, errStr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netsh", "winhttp", "show", "proxy").Output()
	if err != nil {
		return "", "", err.Error()
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(strings.ToLower(line), "proxy server(s)"),
			strings.HasPrefix(strings.ToLower(line), "proxy servers"):
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				proxy = strings.TrimSpace(parts[1])
			}
		case strings.HasPrefix(strings.ToLower(line), "bypass list"):
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				bypass = strings.TrimSpace(parts[1])
			}
		case strings.Contains(strings.ToLower(line), "direct access"):
			proxy = "(none)"
		}
	}
	return proxy, bypass, ""
}

func readInternetSettings(root registry.Key) (proxy, autoCfg string) {
	k, err := registry.OpenKey(root,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`,
		registry.QUERY_VALUE)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	enable, _, _ := k.GetIntegerValue("ProxyEnable")
	if enable == 1 {
		proxy, _, _ = k.GetStringValue("ProxyServer")
	}
	autoCfg, _, _ = k.GetStringValue("AutoConfigURL")
	return proxy, autoCfg
}

func wpadDNSResolves() (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, "wpad")
	if err != nil || len(addrs) == 0 {
		return false, ""
	}
	return true, addrs[0]
}
