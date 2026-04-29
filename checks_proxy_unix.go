//go:build !windows

package main

import "os"

// fillProxyDetect on non-Windows hosts only inspects environment variables.
// The full Windows implementation also reads WinHTTP and WinINET proxy state
// plus WPAD DNS resolution.
func fillProxyDetect(res *Result, c CheckConfig) {
	envHTTP := os.Getenv("HTTP_PROXY")
	envHTTPS := os.Getenv("HTTPS_PROXY")
	envNo := os.Getenv("NO_PROXY")
	configured := envHTTP != "" || envHTTPS != ""

	res.Success = true
	if configured {
		res.Detail = "proxy env vars set (full check is windows-only)"
	} else {
		res.Detail = "no proxy env vars set (full check is windows-only)"
	}
	res.Extra = map[string]any{
		"env_http_proxy":       envHTTP,
		"env_https_proxy":      envHTTPS,
		"env_no_proxy":         envNo,
		"any_proxy_configured": configured,
		"platform":             "non-windows-stub",
	}
}
