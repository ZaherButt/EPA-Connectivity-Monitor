package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// fillHoldOpen establishes a TLS connection to the target and holds it idle for
// HoldFor. It then classifies how the connection died, attributing the close to:
//   - peer_rst:        remote sent RST (firewall/load-balancer aborted)
//   - peer_fin_idle:   remote sent FIN cleanly while idle (server closed)
//   - local_close_after_hold: we closed it after holding the full duration (HEALTHY)
//   - local_read_deadline:    our read deadline expired (HEALTHY, equivalent above)
//   - other:           something else
//
// This is the centerpiece for diagnosing stateful firewall idle-timeouts that
// kill long-lived Service Bus relay sessions used by EPA connectors.
func fillHoldOpen(ctx context.Context, res *Result, c CheckConfig) {
	defaultPort := c.Port
	if defaultPort == 0 {
		defaultPort = 443
	}
	host, port := splitTargetHostPort(c.Target, defaultPort)
	sni := c.TLSServerName
	if sni == "" {
		sni = host
	}
	holdFor := c.HoldFor
	if holdFor == 0 {
		holdFor = 4 * time.Minute
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: c.Timeout, KeepAlive: -1}
	if c.TCPKeepalive {
		dialer.KeepAlive = 30 * time.Second
	}

	t0 := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		res.Detail = fmt.Sprintf("dial %s failed: %v", addr, err)
		return
	}
	tcpDone := time.Now()

	_ = rawConn.SetDeadline(time.Now().Add(c.Timeout))
	tlsConn := tls.Client(rawConn, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		res.Success = false
		res.Error = "tls handshake: " + err.Error()
		res.Detail = fmt.Sprintf("handshake failed against %s (sni=%s)", addr, sni)
		return
	}
	tlsDone := time.Now()
	_ = rawConn.SetDeadline(time.Time{}) // clear any prior deadline

	deadline := time.Now().Add(holdFor)
	_ = rawConn.SetReadDeadline(deadline)

	bytesRead := 0
	buf := make([]byte, 4096)
	var readErr error
	var firstByteAt time.Time
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			n, err := tlsConn.Read(buf)
			if n > 0 {
				if firstByteAt.IsZero() {
					firstByteAt = time.Now()
				}
				bytesRead += n
			}
			if err != nil {
				readErr = err
				return
			}
		}
	}()

	holdCtx, cancel := context.WithTimeout(ctx, holdFor+5*time.Second)
	defer cancel()

	select {
	case <-done:
		// connection died on its own (peer side or read deadline)
	case <-holdCtx.Done():
		// safety net: outer context canceled (service stop)
		_ = tlsConn.Close()
		<-done
	}
	closedAt := time.Now()
	held := closedAt.Sub(tlsDone)
	closedBy, classification := classifyClose(readErr, holdFor, held)

	healthy := classification == "ok_full_hold" || classification == "ok_local_close"
	res.Success = healthy
	res.LatencyMs = msFloat(tlsDone.Sub(t0))
	res.Detail = fmt.Sprintf("held %.1fs/%.0fs against %s closed_by=%s bytes=%d",
		held.Seconds(), holdFor.Seconds(), addr, closedBy, bytesRead)
	if !healthy {
		errMsg := "unknown"
		if readErr != nil {
			errMsg = readErr.Error()
		}
		res.Error = fmt.Sprintf("connection terminated by %s after %.1fs idle: %s",
			closedBy, held.Seconds(), errMsg)
	}

	extra := map[string]any{
		"tcp_connect_ms":   msFloat(tcpDone.Sub(t0)),
		"tls_handshake_ms": msFloat(tlsDone.Sub(tcpDone)),
		"held_seconds":     held.Seconds(),
		"hold_target_sec":  holdFor.Seconds(),
		"bytes_read":       bytesRead,
		"closed_by":        closedBy,
		"classification":   classification,
		"tcp_keepalive":    c.TCPKeepalive,
	}
	if !firstByteAt.IsZero() {
		extra["first_byte_after_ms"] = msFloat(firstByteAt.Sub(tlsDone))
	}
	res.Extra = extra
}

// classifyClose returns (human-readable cause, machine classification).
// Classifications:
//   - ok_full_hold:    held the requested duration without remote interference
//   - ok_local_close:  we closed cleanly (e.g. service stop)
//   - peer_rst:        remote forcibly closed (firewall/middlebox/server)
//   - peer_fin_idle:   remote sent FIN while idle (graceful but unexpected)
//   - other:           something else
func classifyClose(readErr error, holdFor, held time.Duration) (string, string) {
	heldFull := held >= holdFor-500*time.Millisecond

	if readErr == nil {
		if heldFull {
			return "local_close_after_hold", "ok_full_hold"
		}
		return "local_close_early", "ok_local_close"
	}

	var ne net.Error
	if errors.As(readErr, &ne) && ne.Timeout() {
		if heldFull {
			return "local_read_deadline", "ok_full_hold"
		}
		return "local_read_deadline_early", "other"
	}

	if isConnReset(readErr) {
		return "peer_rst", "peer_rst"
	}
	if errors.Is(readErr, io.EOF) {
		return "peer_fin", "peer_fin_idle"
	}
	if errors.Is(readErr, net.ErrClosed) {
		if heldFull {
			return "local_close_after_hold", "ok_full_hold"
		}
		return "local_close_early", "ok_local_close"
	}
	return "other:" + readErr.Error(), "other"
}

func isConnReset(err error) bool {
	var se syscall.Errno
	if errors.As(err, &se) {
		if se == syscall.ECONNRESET {
			return true
		}
	}
	s := err.Error()
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "forcibly closed") ||
		strings.Contains(s, "WSAECONNRESET")
}
