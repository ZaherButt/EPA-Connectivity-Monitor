package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// knownMicrosoftRootSubstrings lists issuer-CN substrings that identify a
// Microsoft-trusted public CA on the chain to *.msappproxy.net,
// *.servicebus.windows.net, login.microsoftonline.com, etc. If the terminal
// issuer in the presented chain matches NONE of these, that's a strong signal
// the chain has been re-issued by a TLS-inspecting middlebox on the customer's
// egress path.
var knownMicrosoftRootSubstrings = []string{
	"DigiCert",
	"Microsoft",
	"Baltimore CyberTrust",
	"GlobalSign",
}

// summarizeCert returns a compact map describing one X.509 cert: subject CN,
// issuer CN, SHA-256 fingerprint (first 16 hex chars), and NotAfter (RFC3339).
func summarizeCert(c *x509.Certificate) map[string]any {
	sum := sha256.Sum256(c.Raw)
	return map[string]any{
		"subject_cn":  c.Subject.CommonName,
		"issuer_cn":   c.Issuer.CommonName,
		"sha256_fp":   hex.EncodeToString(sum[:8]), // 16 hex chars = 8 bytes, plenty for spotting rotation
		"not_after":   c.NotAfter.UTC().Format(time.RFC3339),
		"is_ca":       c.IsCA,
		"dns_names":   c.DNSNames,
		"valid_days":  int(time.Until(c.NotAfter).Hours() / 24),
	}
}

// chainLooksMicrosoftTrusted returns true if the issuer CN of the topmost cert
// in the presented chain contains one of the well-known public CA name
// fragments. False means a private/internal CA terminated the chain — almost
// always TLS interception by a customer firewall/proxy.
func chainLooksMicrosoftTrusted(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	top := chain[len(chain)-1]
	issuer := top.Issuer.CommonName
	for _, want := range knownMicrosoftRootSubstrings {
		if strings.Contains(issuer, want) {
			return true
		}
	}
	return false
}

// fillTLS performs a TCP connect followed by a TLS handshake to the target,
// recording the time spent in each phase. Crucial for distinguishing TLS-inspecting
// middleboxes (slow handshake but fast TCP) from network latency (slow TCP).
func fillTLS(res *Result, c CheckConfig) {
	defaultPort := c.Port
	if defaultPort == 0 {
		defaultPort = 443
	}
	host, port := splitTargetHostPort(c.Target, defaultPort)
	sni := c.TLSServerName
	if sni == "" {
		sni = host
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	t0 := time.Now()
	rawConn, err := net.DialTimeout("tcp", addr, c.Timeout)
	tcpDone := time.Now()
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		res.LatencyMs = msFloat(tcpDone.Sub(t0))
		res.Detail = fmt.Sprintf("tcp dial %s failed in %.2fms", addr, res.LatencyMs)
		return
	}
	defer rawConn.Close()

	_ = rawConn.SetDeadline(time.Now().Add(c.Timeout))
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		tlsDone := time.Now()
		res.Success = false
		res.Error = err.Error()
		res.LatencyMs = msFloat(tlsDone.Sub(t0))
		res.Detail = fmt.Sprintf("tls handshake to %s (sni=%s) failed in %.2fms (tcp %.2fms)",
			addr, sni, msFloat(tlsDone.Sub(tcpDone)), msFloat(tcpDone.Sub(t0)))
		res.Extra = map[string]any{
			"tcp_connect_ms":   msFloat(tcpDone.Sub(t0)),
			"tls_handshake_ms": msFloat(tlsDone.Sub(tcpDone)),
			"sni":              sni,
		}
		return
	}
	tlsDone := time.Now()
	state := tlsConn.ConnectionState()
	_ = tlsConn.Close()

	res.LatencyMs = msFloat(tlsDone.Sub(t0))
	res.Success = true
	res.Detail = fmt.Sprintf("tcp %.2fms + tls %.2fms = %.2fms (proto=%s)",
		msFloat(tcpDone.Sub(t0)), msFloat(tlsDone.Sub(tcpDone)), res.LatencyMs, tlsVersion(state.Version))
	extra := map[string]any{
		"tcp_connect_ms":      msFloat(tcpDone.Sub(t0)),
		"tls_handshake_ms":    msFloat(tlsDone.Sub(tcpDone)),
		"total_ms":            res.LatencyMs,
		"tls_version":         tlsVersion(state.Version),
		"cipher_suite":        fmt.Sprintf("%#x", state.CipherSuite),
		"sni":                 sni,
		"negotiated_protocol": state.NegotiatedProtocol,
	}
	if len(state.PeerCertificates) > 0 {
		extra["server_cert_cn"] = state.PeerCertificates[0].Subject.CommonName
		extra["server_cert_issuer"] = state.PeerCertificates[0].Issuer.CommonName
		chain := make([]map[string]any, 0, len(state.PeerCertificates))
		for _, cert := range state.PeerCertificates {
			chain = append(chain, summarizeCert(cert))
		}
		extra["chain_len"] = len(chain)
		extra["chain"] = chain
		extra["chain_root_issuer"] = state.PeerCertificates[len(state.PeerCertificates)-1].Issuer.CommonName
		extra["chain_known_microsoft_root"] = chainLooksMicrosoftTrusted(state.PeerCertificates)
	}
	res.Extra = extra
}

// fillTLSResume performs two TLS handshakes back-to-back against the same
// target, sharing a TLS session cache between them. The first handshake is
// "cold" (full handshake, no resumption). The second is "warm" (server SHOULD
// resume via session ticket / TLS 1.3 PSK). Reports per-handshake timing,
// whether resumption actually happened, and the delta — directly addressing
// the common claim "latency only occurs on the first connection".
func fillTLSResume(res *Result, c CheckConfig) {
	defaultPort := c.Port
	if defaultPort == 0 {
		defaultPort = 443
	}
	host, port := splitTargetHostPort(c.Target, defaultPort)
	sni := c.TLSServerName
	if sni == "" {
		sni = host
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// Shared session cache so handshake #2 can reuse #1's ticket.
	cache := tls.NewLRUClientSessionCache(4)
	cfg := &tls.Config{
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: cache,
	}

	doHandshake := func() (tcpMs, tlsMs float64, didResume bool, version uint16, err error) {
		t0 := time.Now()
		raw, dialErr := net.DialTimeout("tcp", addr, c.Timeout)
		tcpDone := time.Now()
		if dialErr != nil {
			return msFloat(tcpDone.Sub(t0)), 0, false, 0, dialErr
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(c.Timeout))
		conn := tls.Client(raw, cfg)
		if hsErr := conn.Handshake(); hsErr != nil {
			tlsDone := time.Now()
			return msFloat(tcpDone.Sub(t0)), msFloat(tlsDone.Sub(tcpDone)), false, 0, hsErr
		}
		tlsDone := time.Now()
		st := conn.ConnectionState()
		// Read briefly to give the server a chance to push NewSessionTicket
		// (TLS 1.3 sends it as application data after the handshake completes).
		// We don't care about the data — the ticket is processed by the
		// underlying tls package when it arrives, populating the cache.
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_ = conn.Close()
		return msFloat(tcpDone.Sub(t0)), msFloat(tlsDone.Sub(tcpDone)), st.DidResume, st.Version, nil
	}

	coldTCP, coldTLS, coldResume, coldVer, coldErr := doHandshake()
	if coldErr != nil {
		res.Success = false
		res.Error = coldErr.Error()
		res.LatencyMs = coldTCP + coldTLS
		res.Detail = fmt.Sprintf("cold handshake to %s failed: %v", addr, coldErr)
		res.Extra = map[string]any{
			"cold_tcp_ms": coldTCP,
			"cold_tls_ms": coldTLS,
			"sni":         sni,
		}
		return
	}

	warmTCP, warmTLS, warmResume, warmVer, warmErr := doHandshake()
	if warmErr != nil {
		res.Success = false
		res.Error = warmErr.Error()
		res.LatencyMs = coldTCP + coldTLS
		res.Detail = fmt.Sprintf("warm handshake to %s failed: %v", addr, warmErr)
		res.Extra = map[string]any{
			"cold_tcp_ms":     coldTCP,
			"cold_tls_ms":     coldTLS,
			"cold_did_resume": coldResume,
			"sni":             sni,
		}
		return
	}

	res.Success = true
	res.LatencyMs = coldTCP + coldTLS
	delta := coldTLS - warmTLS
	res.Detail = fmt.Sprintf("cold tls=%.2fms (proto=%s, resumed=%v) | warm tls=%.2fms (proto=%s, resumed=%v) | delta=%.2fms",
		coldTLS, tlsVersion(coldVer), coldResume,
		warmTLS, tlsVersion(warmVer), warmResume,
		delta)
	res.Extra = map[string]any{
		"cold_tcp_ms":     coldTCP,
		"cold_tls_ms":     coldTLS,
		"cold_did_resume": coldResume,
		"cold_version":    tlsVersion(coldVer),
		"warm_tcp_ms":     warmTCP,
		"warm_tls_ms":     warmTLS,
		"warm_did_resume": warmResume,
		"warm_version":    tlsVersion(warmVer),
		"delta_tls_ms":    delta,
		"sni":             sni,
	}
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
