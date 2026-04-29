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
| `proxy_detect`  | One DNS lookup for the bare name `wpad`. No traffic to any proxy. |
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
- for `proxy_detect`: snapshot of local proxy configuration from env vars,
  `netsh winhttp show proxy` output, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
  registry values (per-machine and per-user), and whether the bare DNS name
  `wpad` resolves. All read-only; no proxy is ever contacted.

The log does **not** contain:

- packet payloads, packet captures, or any application-layer data
- credentials, tokens, certificates' private keys, API keys
- user identifiers, mail addresses, device identifiers
- any data from outside the configured probe targets

You control retention via `log_max_size_mb`, `log_max_backups`,
`log_max_age_days` — see `config.example.yaml`.

## Can I share the log file? Is there anything sensitive in it?

The log is plain-text JSON-Lines and human-readable — open it in Notepad
before sharing if you want to confirm exactly what is in it. The categories
of data it contains are:

**What is NOT in the log:**

- ❌ Usernames, UPNs, email addresses, principal names
- ❌ Passwords, tokens, secrets, certificate private keys
- ❌ Tenant IDs, Azure subscription IDs, app traffic, payload content
- ❌ Browsing history, file content, screen activity, anything from outside
  the configured probe targets

**What IS in the log (default config):**

| Field | Example | Sensitivity |
|---|---|---|
| Configured target hostnames | `cwap-eur1-weur2.servicebus.windows.net` | Public Microsoft endpoints — not sensitive |
| Resolved public IPs | `52.142.x.x` | Public Microsoft infrastructure |
| Connector machine hostname | `EPA01` | Customer-chosen device name |
| Default gateway IP | `192.168.1.1` | Internal infra address (not personal data) |
| Latency / timing numbers | `47.10ms` | Not sensitive |
| TLS server cert metadata (CN, Issuer, SAN, NotAfter) | `*.servicebus.windows.net` / `Microsoft RSA TLS CA 02` | Public certificate metadata served by every TLS endpoint |
| Connection error strings from the OS | `connection reset by peer` | Not sensitive |

**Two narrow caveats — review before sharing:**

1. **`tracert` output** is captured only on a failed check. The hop list can
   include **internal router IPs and reverse-DNS names** along the path inside
   the customer network. Not personal PII, but some organisations classify
   internal network topology as sensitive infrastructure information. If that
   applies to you, scrub the `extra.tracert` arrays from failed entries before
   sharing the log externally.

2. **`log_tail`** — disabled by default. If you enable it and point it at a
   file (e.g. an EPA connector log) with a regex like `error|fail`, the
   matched lines are captured **verbatim** in the JSON log. Those lines could
   contain whatever the source application logs — tenant ID GUIDs, connector
   names, internal application names, internal URLs being proxied, etc. Only
   enable `log_tail` against files you are comfortable sharing the contents
   of. The captured lines appear under `extra.matches`.

**Practical bottom line:** in the default configuration (no `log_tail`),
the worst-case sensitive content is the local gateway IP plus possibly a few
internal router hops on a failed `tracert`. Open the file in Notepad, search
for any of the above before sending — the format is one self-contained JSON
object per line, so you can edit/redact freely with any text editor.

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
