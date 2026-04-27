//go:build !windows

package main

import (
	"fmt"
	"runtime"
)

// fillHostHealth on non-Windows is a stub for local development. The Windows
// build provides full host metrics.
func fillHostHealth(res *Result) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	res.Success = true
	res.Detail = fmt.Sprintf("self_alloc=%.1fMB goroutines=%d (host metrics windows-only)",
		float64(ms.Alloc)/1024/1024, runtime.NumGoroutine())
	res.Extra = map[string]any{
		"self_alloc_mb": float64(ms.Alloc) / 1024 / 1024,
		"goroutines":    runtime.NumGoroutine(),
	}
}
