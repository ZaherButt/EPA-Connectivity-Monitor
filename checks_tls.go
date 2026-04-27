package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"
)

// fillTLS performs a TCP connect followed by a TLS handshake to the target,
// recording the time spent in each phase. Crucial for distinguishing TLS-inspecting
// middleboxes (slow handshake but fast TCP) from network latency (slow TCP).
func fillTLS(res *Result, c CheckConfig) {
	port := c.Port
	if port == 0 {
		port = 443
	}
	sni := c.TLSServerName
	if sni == "" {
		sni = c.Target
	}
	addr := net.JoinHostPort(c.Target, strconv.Itoa(port))

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
	}
	res.Extra = extra
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
