//go:build windows

package main

import (
	"golang.org/x/sys/windows/registry"
)

// loadConnectorIDs reads the EPA connector's tenant ID and connector ID from
// the Windows registry. The connector has been rebranded multiple times
// ("App Proxy" -> "Azure AD App Proxy" -> "Microsoft Entra private network
// connector") and each generation has used slightly different registry paths,
// so we probe a list of known locations and return on the first hit.
//
// Returns ("", "", "") if no connector is installed (e.g. running this binary
// on a generic Windows box for testing). Returns the source path alongside
// the IDs so we can stamp it on the startup log line for diagnostics.
func loadConnectorIDs() (tenantID, connectorID, source string) {
	candidates := []string{
		`SOFTWARE\Microsoft\Microsoft Entra private network connector`,
		`SOFTWARE\Microsoft\Entra\PrivateNetworkConnector`,
		`SOFTWARE\Microsoft\Microsoft AAD App Proxy Connector`,
		`SOFTWARE\Microsoft\Azure AD App Proxy Connector`,
		`SOFTWARE\Microsoft\AzureAD App Proxy Connector`,
	}
	tenantValueNames := []string{"TenantId", "TenantID", "Tenant"}
	connectorValueNames := []string{"ConnectorId", "ConnectorID", "Connector"}

	for _, path := range candidates {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		var tID, cID string
		for _, n := range tenantValueNames {
			if v, _, e := k.GetStringValue(n); e == nil && v != "" {
				tID = v
				break
			}
		}
		for _, n := range connectorValueNames {
			if v, _, e := k.GetStringValue(n); e == nil && v != "" {
				cID = v
				break
			}
		}
		_ = k.Close()
		if tID != "" || cID != "" {
			return tID, cID, `HKLM\` + path
		}
	}
	return "", "", ""
}
