//go:build !windows

package main

// loadTenantID is a no-op on non-Windows (the EPA connector only runs on
// Windows Server). Returning empty strings causes the logger to omit the
// tenant_id field from log entries, keeping the JSON clean during
// dev/test on Mac and Linux.
func loadTenantID() (tenantID, source string) {
	return "", ""
}
