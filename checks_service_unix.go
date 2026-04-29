//go:build !windows

package main

// fillServiceStatus is a Windows-only check; the EPA connector only runs on
// Windows Server. On other platforms we return a clear stub result so the
// check appears in dev logs as "skipped" rather than producing confusing
// errors.
func fillServiceStatus(res *Result, c CheckConfig) {
	res.Success = true
	res.Detail = "service_status check skipped: not Windows"
	res.Extra = map[string]any{
		"skipped":        true,
		"skipped_reason": "non_windows_platform",
	}
}
