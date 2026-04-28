# Security and trust

This document explains what `epa-connectivity-monitor.exe` does and does not
do, so a security-conscious operator can decide whether to run it without
having to read every line of source (though the source is right here next
to it — please do).

## TL;DR

- **No telemetry, no auto-update, no callback.** The binary makes outbound
  connections **only** to the targets listed in your `config.yaml` and (if
  enabled) `tracert` to those same targets.
- **No credentials, no certificates, no user data are collected.** The log is
  plain-text JSON-Lines containing only hostnames/IPs you configured + timing
  numbers + classification of how a probe ended.
- **No inbound listener.** The process never opens a listening socket.
- **Local-only.** Logs are written to disk on the host that ran them. Nothing
  is ever uploaded anywhere by the tool. If you choose to share a log with
  Microsoft Support, that is an explicit human action.
- **Bounded disk usage.** The log file is rotated automatically. With the
  default settings the active file rolls at **500 MB**, up to **9 backups**
  are kept (each gzip-compressed — typically 30–60 MB for this JSONL format),
  and anything older than **7 days** is deleted. Realistic steady-state
  footprint on disk at typical EPA check rates: **~500 MB – 1 GB**. Absolute
  worst case before age-based cleanup: **~5 GB** (1 active file + 9 compressed
  backups). On top of that, the logger checks free disk space on the log
  volume every 30 seconds and **stops writing to disk if free space drops
  below `log_min_free_disk_mb` (default 5120 MB / 5 GB)** — console output
  continues, and writes resume automatically once space is freed. All four
  thresholds are overridable via `log_max_size_mb`, `log_max_backups`,
  `log_max_age_days`, `log_min_free_disk_mb` in `config.yaml`. The tool will
  not silently fill the disk.
- **Open source.** All ~2k lines of Go are in this repository. The release
  artefact is reproducible from this source.

## What network traffic does it generate?

Every check is documented in `README.md`. Briefly, the only outbound traffic is:

| Check type      | Traffic                                                  |
|-----------------|----------------------------------------------------------|
| `gateway_ping`  | ICMP echo to your auto-discovered default gateway        |
| `internet_ping` | ICMP echo to the configured public IP (e.g. `9.9.9.9`)   |
| `tcp443`        | TCP SYN to port 443 of the configured target, then close |
| `dns_a`         | UDP/TCP DNS A-record query to the configured resolver    |
| `tls`           | TCP+TLS handshake to `target:port`, then close           |
| `tls_resume`    | Two back-to-back TCP+TLS handshakes to `target:port` (cold + warm), each closed immediately after the handshake completes |
| `holdopen`      | TCP+TLS to `target:port`, held idle for `hold_for`       |
| `host_health`   | None. Reads only local OS counters.                      |
| `log_tail`      | None. Reads only the configured local file.              |
| `trace_on_failure` | Spawns `tracert.exe` against the failing target's IP  |

Use `epa-connectivity-monitor.exe --print-config` to print the full effective
configuration (every target, every interval) before installing the service.

## What does it write to disk?

A single rotating JSON-Lines log file (`epa-connectivity-monitor.log` by
default) in the install directory. Each line is one check result with fields
like `timestamp`, `check`, `type`, `target`, `success`, `latency_ms`, and
optionally an `extra` object with structured detail.

The log contains:

- timing numbers (`latency_ms`, `tls_handshake_ms`, `cold_tls_ms`, `warm_tls_ms`, etc.)
- the hostnames and IP addresses **you yourself configured** as probe targets
- DNS resolver IPs you configured
- the local default-gateway IP (auto-discovered, never sent anywhere)
- TLS server certificate metadata for the chain presented by the server: per
  cert the public Subject CN, Issuer CN, SHA-256 fingerprint (truncated),
  NotAfter date, `is_ca` flag, and SAN DNS names. This is **public information**
  presented by the server during every TLS handshake. **No private keys** are
  ever read or written.
- whether a TLS handshake resumed a prior session (`tls_resume` check only)
- error strings from the OS networking stack (e.g. `connection reset by peer`)
- for `host_health`: aggregate CPU%, free memory, TCP connection counts, no
  per-process or per-user information
- for `log_tail`: lines from a file path **you configured** that match a regex

The log does **not** contain:

- packet payloads, packet captures, or any application-layer data
- credentials, tokens, certificates' private keys, API keys
- user identifiers, mail addresses, device identifiers
- any data from outside the configured probe targets

You control retention via `log_max_size_mb`, `log_max_backups`,
`log_max_age_days` — see `config.example.yaml`.

## What permissions does it need?

- **`LocalSystem`** when installed as a Windows service. This is the standard
  Windows service account; the tool does not use any rights granted by it
  beyond opening sockets and reading local counters. No domain rights, no
  Azure / Entra credentials, no certificate-store access, no registry write
  access outside the standard service-installation keys.
- **Administrator** is required *only* for ICMP checks (raw sockets). All
  other check types work without elevation.
- The install directory is the only filesystem path written to. No writes to
  `%SystemRoot%`, `%ProgramData%`, the registry (beyond the service key), or
  the user profile.

## How can I verify the binary?

Each tagged release attaches:

1. The `epa-connectivity-monitor.exe` binary
2. A `SHA256SUMS.txt` file with the SHA-256 of the binary
3. A `sbom.txt` file produced by `go version -m` listing every Go module
   compiled into the binary, with version pins

Verify on Windows:

```cmd
certutil -hashfile epa-connectivity-monitor.exe SHA256
type SHA256SUMS.txt
```

Verify on macOS / Linux:

```sh
sha256sum -c SHA256SUMS.txt
```

## How can I reproduce the build myself?

```sh
git clone https://github.com/ZaherButt/EPA-Connectivity-Monitor.git
cd EPA-Connectivity-Monitor
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o epa-connectivity-monitor.exe .
sha256sum epa-connectivity-monitor.exe
```

Match the published `SHA256SUMS.txt` — if it matches, the published binary
was built from this exact source tree.

## How do I uninstall?

```cmd
epa-connectivity-monitor.exe --uninstall
```

This stops the service, deletes the service registration, and removes the
event-log source. The install directory (binary + config + logs) is left in
place so you can inspect anything before deleting it manually.

## Reporting a security issue

If you find a security issue in this tool, please **do not** open a public
GitHub issue. Email the repository owner privately via the address listed on
their GitHub profile.
