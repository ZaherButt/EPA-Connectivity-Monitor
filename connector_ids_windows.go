//go:build windows

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// loadTenantID reads the EPA connector's tenant ID from the same on-disk
// source that Microsoft's own ConnectorDiagnosticsTool reads (confirmed via
// ProcMon trace on EPA01, 29 Apr 2026):
//
//	%ProgramData%\Microsoft\Microsoft Entra private network connector\Endpoints\endpoints.txt
//
// The file is JSON; the tenant GUID is embedded in the Bootstrap URL as the
// hostname's leftmost label:
//
//	https://<TENANT_GUID>.bootstrap.msappproxy.net/
//
// We deliberately use a regex rather than a full unmarshal so the parser
// tolerates schema drift if Microsoft renames a field.
//
// There is no equivalent connector_id source on disk. The connector ID is
// server-assigned and only obtainable via an authenticated bootstrap call
// into Azure with the connector's client cert. Replicating that is out of
// scope for a passive diagnostic tool, so we drop the field entirely.
//
// Returns ("", "") when the file is missing (e.g. a non-connector host or a
// pre-Entra rebrand install where the layout differs).
func loadTenantID() (tenantID, source string) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	path := filepath.Join(programData, "Microsoft", "Microsoft Entra private network connector",
		"Endpoints", "endpoints.txt")

	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	re := regexp.MustCompile(`https://([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\.bootstrap\.msappproxy\.net`)
	m := re.FindSubmatch(data)
	if len(m) < 2 {
		return "", ""
	}
	return strings.ToLower(string(m[1])), `endpoints.txt`
}
