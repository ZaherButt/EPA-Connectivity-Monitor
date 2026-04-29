//go:build !windows

package main

// loadConnectorIDs is a no-op on non-Windows (the EPA connector only runs on
// Windows Server). Returning empty strings causes the logger to omit the
// tenant/connector ID fields from log entries, keeping the JSON clean during
// dev/test on Mac and Linux.
func loadConnectorIDs() (tenantID, connectorID, source string) {
	return "", "", ""
}
