# EPA Connectivity Monitor

> ⚠️ **Community diagnostic tool — not a Microsoft product.** No warranty, no
> support contract. See [`DISCLAIMER.md`](DISCLAIMER.md). For official Entra
> Private Access support, contact Microsoft via your organisation's standard
> support channel.

Standalone Windows tool that periodically checks network connectivity and writes
results to a rotating JSON-Lines log file. Built to capture independent
network observations from a connector host's vantage point so root-cause
discussions can be grounded in data.

**Specifically designed to surface the silent middlebox problems** that the
EPA connector agent itself doesn't report:

- **Undeclared proxy / WPAD** — snapshots `HTTP_PROXY` env vars, WinHTTP, WinINET (HKLM + HKCU), and WPAD DNS auto-discovery on every run, so you know whether the connector is being routed through a forward proxy the customer's network team forgot to mention.
- **TLS interception (SSL inspection)** — captures the full server certificate chain on every TLS handshake and flags `chain_known_microsoft_root: false` whenever the cert isn't actually signed by Microsoft / a known public CA. That's the unambiguous signature of an in-line decrypting proxy (Zscaler, Netskope, Palo Alto, Forcepoint, Fortinet etc.).
- **Aggressive idle-connection killing** — `holdopen` checks hold a TLS connection open for 4 minutes and report exactly when (and how — `peer_fin` vs `peer_rst`) it gets cut. Distinguishes legitimate upstream timeouts from middlebox enforcement.
- **Asymmetric latency split** — `tls` reports TCP-connect time and TLS-handshake time as separate metrics, so a small TCP + huge TLS pattern (CDN edge terminating TCP, real cluster terminating TLS in another region) is obvious at a glance.

> **Trust & security:** see [`SECURITY.md`](SECURITY.md) for what the tool does
> and does not do (no telemetry, no auto-update, no credential access, local
> logs only) and how to verify the published binary against this source tree.

## Check types

Each check is documented below as a self-contained reference:
**What it does · Why it matters · Healthy looks like · Red flag · Key fields**.

> **ICMP elevation note (only relevant for interactive CLI testing).** When
> installed as a Windows service (`epa-connectivity-monitor.exe -install`)
> the service runs as **LocalSystem**, which has the rights ICMP needs — no
> action required. If you're running the `.exe` directly from a `cmd` window
> for testing, launch that `cmd` "as Administrator" or `gateway_ping` /
> `internet_ping` will be **automatically skipped** — the tool detects the
> permission error on the first attempt, prints a one-time WARN to stderr
> explaining how to enable ICMP, and emits subsequent ICMP results with
> `success: true`, `detail: "ICMP skipped: process not elevated, raw sockets
> unavailable"` and `extra.skipped: true` so the log isn't polluted with
> false failures. All other check types (TCP, TLS, DNS, holdopen,
> host_health, log_tail, proxy_detect, tracert) work fine unelevated either
> way.

---

### `gateway_ping`
- **What it does:** auto-discovers the default gateway and sends ICMP echo (3 packets).
- **Why it matters:** isolates the very first hop. If this fails while everything else is fine you have a host-NIC / local-LAN problem; if this succeeds while `internet_ping` fails the egress is at fault, not the connector.
- **Healthy looks like:** `success=true`, `latency_ms` < 5 ms on a wired LAN, `packet_loss_pct=0`.
- **Red flag:** any loss, or sudden latency steps — points at a flapping NIC, switch port, or a virtualised gateway under contention.
- **Key fields:** `latency_ms`, `packet_loss_pct`, `detail` (sent/recv/loss/avg).

### `internet_ping`
- **What it does:** ICMP echo to a configured public IP (e.g. Quad9 `9.9.9.9`).
- **Why it matters:** lowest-cost continuous proof that the internet path from this host works at all. Quad9 is chosen because most corporate egress firewalls allow ICMP to it.
- **Healthy looks like:** `success=true`, stable `latency_ms` (typically 5–40 ms), zero loss.
- **Red flag:** rising loss correlated with user-reported outages = upstream WAN/ISP issue, not application.
- **Key fields:** `latency_ms`, `packet_loss_pct`.

### `tcp443`
- **What it does:** TCP connect to port 443 on the target hostname.
- **Why it matters:** answers "is the layer-4 path open right now?" without doing a TLS handshake. Cheap, fast, can be polled every few seconds.
- **Healthy looks like:** `success=true`, `latency_ms` of one round-trip to the target.
- **Red flag:** intermittent failures while ICMP stays clean → upstream stateful firewall or load-balancer dropping SYNs. Pair with `trace_on_failure: true`.
- **Key fields:** `latency_ms`, `detail`.

### `dns_a`
- **What it does:** A-record lookup for `target`, sent directly to a specified `resolver` (bypasses OS resolver cache and search-list).
- **Why it matters:** decouples DNS from the rest. If `tcp443` fails but `dns_a` to `1.1.1.1` works, the problem is the upstream firewall, not name resolution. If `dns_a` itself is slow or returns NXDOMAIN you've found a DNS-server problem.
- **Healthy looks like:** `success=true`, `latency_ms` < 30 ms, ≥ 1 record returned.
- **Red flag:** wildly different answers from internal vs external resolvers (split-horizon misconfig pointing connector at the wrong endpoint).
- **Key fields:** `resolver`, `latency_ms`, `detail` (record count + IPs).

### `tls`
- **What it does:** opens a TCP connection then a TLS handshake to `target:port` (default 443). Reports **TCP-connect time and TLS-handshake time as separate metrics**, plus the **full server certificate chain** (subject CN, issuer CN, SHA-256 fingerprint, expiry per cert) and a `chain_known_microsoft_root` flag set when the chain terminates at a known public CA.
- **Why it matters:** the headline diagnostic. A TLS-inspecting middlebox, a far-region backend, or an overloaded TLS terminator all *look the same* to a plain `tcp443` check but produce a distinctive split here. The chain dump turns "is there a TLS-intercepting proxy in the path?" from a hard question into a glance — if `chain_root_issuer` isn't a recognised public CA (DigiCert, Microsoft, Baltimore, GlobalSign), there is.
- **Healthy looks like:** TLS handshake roughly 1–3× the TCP-connect time. TLS1.3, expected SNI, `chain_known_microsoft_root: true`, leaf issuer is a Microsoft public CA.
- **Red flag:** TCP-connect tiny (e.g. 5 ms) but TLS-handshake huge (e.g. 400 ms) → TLS payload is traversing further than the TCP terminator (CDN/edge LB pattern, or far-region backend). `chain_known_microsoft_root: false` or a `chain_root_issuer` matching the customer's firewall/proxy product → TLS-inspecting proxy is in the path.
- **Key fields:** `extra.tcp_connect_ms`, `extra.tls_handshake_ms`, `extra.tls_version`, `extra.sni`, `extra.cipher_suite`, `extra.server_cert_cn`, `extra.server_cert_issuer`, `extra.chain_len`, `extra.chain_root_issuer`, `extra.chain_known_microsoft_root`, `extra.chain` (array of `subject_cn` / `issuer_cn` / `sha256_fp` / `not_after` / `valid_days` / `is_ca` / `dns_names`).

### `tls_resume`
- **What it does:** performs **two** back-to-back TLS handshakes against the same target with a shared session cache. The first is "cold" (full handshake); the second is "warm" (server *should* resume via TLS-1.3 PSK or TLS-1.2 session ticket if it issues one). Reports both timings, the delta, and whether the warm handshake actually resumed.
- **Why it matters:** directly tests the common Microsoft-Support framing *"latency only occurs on the first connection"*. If a server issues session tickets and the customer's egress preserves them, warm handshakes are dramatically cheaper than cold ones — that's the "first connection only" pattern. If the warm handshake takes the same time as cold (or `warm_did_resume: false`), the claim doesn't hold for that endpoint and every reconnect pays the full cost.
- **Healthy looks like:** `cold_did_resume: false`, `warm_did_resume: true`, `delta_tls_ms` materially > 0 (warm faster than cold). Example: cold 35 ms, warm 9 ms, delta 26 ms.
- **Red flag:** `warm_did_resume: false` consistently → the server isn't issuing session tickets (e.g. Service Bus relay endpoints don't, so connector reconnects always pay full handshake — important context when MSFT support invokes the "first connection only" argument). `warm_did_resume: true` but `delta_tls_ms` ≈ 0 → resumption is happening but a middlebox is doing a fresh handshake on the customer-side leg anyway.
- **Key fields:** `extra.cold_tcp_ms`, `extra.cold_tls_ms`, `extra.cold_did_resume`, `extra.cold_version`, `extra.warm_tcp_ms`, `extra.warm_tls_ms`, `extra.warm_did_resume`, `extra.warm_version`, `extra.delta_tls_ms`, `extra.sni`.

### `holdopen`
- **What it does:** opens a TLS connection and holds it idle (no traffic) for `hold_for` (default 4m). When the connection eventually dies, classifies the cause.
- **Why it matters:** EPA / Service Bus relay traffic uses long-lived idle connections. Stateful firewalls and NAT devices silently kill idle flows after 60s / 120s / 300s. This is the only check that proves *long-session survival* — and the classification (`peer_rst` vs `peer_fin_idle` vs `ok_full_hold`) attributes the cause.
- **Healthy looks like:** `classification=ok_full_hold`, `held_seconds ≈ hold_target_sec`.
- **Red flag:** consistent `peer_rst` at the same `held_seconds` across many runs (e.g. always ~125 s) → stateful firewall idle-timeout on the path. `peer_fin_idle` at the same cadence = upstream backend's own idle policy (less actionable, but still attributable).
- **Key fields:** `extra.held_seconds`, `extra.hold_target_sec`, `extra.closed_by`, `extra.classification`, `extra.tcp_keepalive`.

### `host_health`
- **What it does:** snapshot of the local Windows host: CPU %, memory free, TCP established count, TCP retransmits / sec, RST send/recv / sec.
- **Why it matters:** pre-empts "your connector host is overloaded" pushback. Also surfaces TCP retransmits — a high-quality leading indicator of network trouble even when nothing is failing yet.
- **Healthy looks like:** CPU steady < 60 %, memory free trending flat, retransmits / sec near zero.
- **Red flag:** sudden retransmit spike correlated with user-reported failures → packet loss on the egress. CPU pegged → the host is the bottleneck, not the network.
- **Key fields:** `extra.cpu_percent`, `extra.mem_free_mb`, `extra.tcp_established`, `extra.retransmits_per_sec`, `extra.rst_sent_per_sec`, `extra.rst_recv_per_sec`.

### `log_tail`
- **What it does:** tails a file at `log_path`, emits one record per new line matching `pattern` (default regex: `error|warn|fail|exception|disconnect`).
- **Why it matters:** correlates user-reported events to **connector-internal** errors at the same wallclock time. Without this you only see what the *outside* of the connector looks like; with it you also see what the connector itself is complaining about.
- **Healthy looks like:** no records emitted (no matching lines) during normal operation.
- **Red flag:** burst of matches aligned with a user-reported outage window → root cause is on the connector itself, not the network.
- **Key fields:** `extra.line`, `extra.matched_pattern`, `extra.file_offset`.

### `proxy_detect`
- **What it does:** read-only snapshot of every place a Windows host might be configured to use an HTTP/HTTPS proxy: `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` env vars, `netsh winhttp show proxy`, `HKLM` + `HKCU` Internet Settings (proxy server + AutoConfigURL/PAC), and a single DNS lookup for `wpad` to detect WPAD auto-discovery.
- **Why it matters:** EPA traffic going through an undeclared proxy is a top-3 silent cause of "feels slow" tickets. A transparent forwarding proxy can sit invisibly between the connector and Microsoft endpoints. Pair this with `tls`/`tls_resume`: those flag `chain_known_microsoft_root: false` when a proxy is *actively decrypting* TLS — `proxy_detect` shows you whether one is *configured* in the first place.
- **Healthy looks like:** `extra.findings: []`, `extra.any_proxy_configured: false`, all five sources clean.
- **Red flag:** any non-empty `extra.findings` array — `env_proxy`, `winhttp`, `wininet`, `pac_url`, or `wpad`. Cross-reference with the cert-chain results from your `tls` checks to determine whether the proxy is just routing or also intercepting.
- **Key fields:** `extra.findings`, `extra.any_proxy_configured`, `extra.winhttp_proxy`, `extra.wininet_hklm_proxy`, `extra.wininet_hkcu_proxy`, `extra.wpad_dns_resolves`.
- **Traffic generated:** none, except one DNS lookup for the bare name `wpad` per run.

### `service_status`
- **What it does:** queries the Windows Service Control Manager for a named service and reports whether it's currently in the `Running` state. Surfaces the configured start type (Automatic/Manual/Disabled), the last Win32 exit code, the run-as account, and (for running services) the PID + process uptime so you can see when the service last restarted.
- **Why it matters:** if the EPA connector service dies at 03:00 and SCM hasn't auto-restarted it yet, the next interval's log entry records it instead of you finding out from a user ticket the next morning. Pair with `holdopen` and `tls` so you can correlate "service stopped" against "outbound traffic stopped working" in the same log.
- **Configuration:** set `target` to the service name, e.g. `WAPCSvc` for the EPA connector. Use `sc query state= all` from an elevated prompt to discover the exact name on a given build of the connector.
- **Healthy looks like:** `success: true`, `extra.state: "Running"`, increasing `extra.uptime_seconds` between log entries.
- **Red flag:** `success: false` — service stopped, in StopPending/StartPending for more than one interval, or showing a non-zero `extra.win32_exit`. A sudden reset of `extra.uptime_seconds` to a small number means the service has just restarted.
- **Key fields:** `extra.state`, `extra.start_type`, `extra.win32_exit`, `extra.pid`, `extra.uptime_seconds`, `extra.started_at`, `extra.run_as`, `extra.binary_path`, `extra.display_name`.
- **Traffic generated:** none — pure local SCM IPC.

### Snapshot mode (`--snapshot`)

For a one-shot health check without writing the JSON log, use `--snapshot`:

```cmd
epa-connectivity-monitor.exe --config config.yaml --snapshot
```

Runs every configured check exactly once in parallel, prints a colour-coded
PASS/FAIL summary table to stdout, and exits with code 0 (all passed) or 1
(any failed). No log file is written. Useful for engineers who want a quick
"is this box healthy right now?" answer before installing the service or
while remoted into a customer connector.

> Note: snapshot mode is **not** a substitute for continuous monitoring.
> Most of the problems this tool exists to catch — intermittent latency
> spikes, hold-open resets, asymmetric path failures — only show up over
> time and require the long-running mode.

### Source host + EPA connector tenant_id in every log entry

Every JSON log record carries a top-level `host` field set to `os.Hostname()`
at startup. This means logs from multiple connectors / lab boxes can be
shipped into the same place and immediately disambiguated:

```json
{"timestamp":"2026-04-29T17:24:50Z","host":"epa01","check":"servicebus-uk",
 "type":"tls","success":true,"latency_ms":42.1,
 "extra":{"tenant_id":"72f988bf-86f1-41af-91ab-2d7cd011db47","tls_version":"TLS1.3"}}
```

When run on a Windows host that has the Microsoft Entra private network
connector installed, the binary additionally reads the `tenant_id` from the
connector's on-disk config (`%ProgramData%\Microsoft\Microsoft Entra private network connector\Endpoints\endpoints.txt`)
once at startup and stamps it into the `extra` block of every JSON log
record.

This means a support engineer reading a shared log can immediately tell
which host produced it, and which tenant it belongs to, without
back-and-forth. If no connector is installed (e.g. running on a generic
Windows box for testing) the `tenant_id` field is simply omitted; `host`
is always present. See [`SECURITY.md`](SECURITY.md) for guidance on
redacting these fields before sharing logs with third parties.

> Note: there is intentionally no `connector_id` field. The connector ID is
> server-assigned by Azure during bootstrap and not stored anywhere on the
> connector host (verified by ProcMon trace of Microsoft's
> ConnectorDiagnosticsTool). Replicating Azure's bootstrap call would
> require client-cert TLS into Microsoft endpoints with the connector's
> private key — out of scope for a passive diagnostic tool. The `tenant_id`
> alone is sufficient for cross-host log correlation.

---

### Auto-tracert on failure

Add `trace_on_failure: true` to **any** check. When the check fails, the binary
runs `tracert.exe` against the failing target and embeds hop-by-hop output in the
JSON record's `extra.tracert` array. Optional `max_hops:` (default 20). Optional
on healthy probes too — but it's noisy, so usually only worth enabling on the
endpoints whose failures you actually need to escalate.

```yaml
- name: "epa-sb-eur1-weur2"
  type: "tcp443"
  target: "cwap-eur1-weur2.servicebus.windows.net"
  trace_on_failure: true
  max_hops: 25
```

### Combining checks into an evidence pack

The diagnostic check types are designed to *combine* into a structured evidence pack:

1. **`tls`** against each Service Bus relay endpoint — proves where the time goes
   (TCP vs TLS), surfaces the full server certificate chain, and flags whether
   the chain terminates at a known Microsoft public CA (a `false` here is
   strong evidence of a TLS-inspecting middlebox).
2. **`tls_resume`** against each endpoint — empirically tests the common claim
   *"latency only occurs on the first connection"* by doing back-to-back cold +
   warm handshakes and reporting whether session resumption was actually offered
   and whether it materially helped.
3. **`holdopen` (4m)** against each Service Bus relay endpoint — proves whether
   long-lived sessions survive, and *attributes* who killed them (`peer_rst` =
   stateful FW on the path; `peer_fin_idle` = upstream policy).
4. **`host_health`** — pre-empts "your connector host is overloaded" pushback.
5. **`log_tail`** of the connector's own trace log — correlates user-reported
   issues with connector-internal events at the same wallclock time.
6. **`trace_on_failure`** — every TCP/TLS failure is automatically annotated
   with a tracert, showing exactly which hop the path dies at.

## Releases & verifying the binary

Each tagged release at
[**Releases**](https://github.com/ZaherButt/EPA-Connectivity-Monitor/releases)
attaches three files, all built by [`.github/workflows/release.yml`](.github/workflows/release.yml)
from the tagged commit on this repository:

| File                              | Purpose                                                  |
|-----------------------------------|----------------------------------------------------------|
| `epa-connectivity-monitor.exe`    | The Windows amd64 binary (no installer, just copy & run) |
| `config.example.yaml`             | Example configuration — rename to `config.yaml` and edit |
| `SHA256SUMS.txt`                  | SHA-256 hash of the binary                               |
| `sbom.txt`                        | `go version -m` output: every Go module + version baked in |

**Verify on Windows (cmd):**

```cmd
certutil -hashfile epa-connectivity-monitor.exe SHA256
type SHA256SUMS.txt
```

**Verify on macOS / Linux:**

```sh
sha256sum -c SHA256SUMS.txt
```

**Reproduce the build yourself** (any OS with Go installed):

```sh
git clone https://github.com/ZaherButt/EPA-Connectivity-Monitor.git
cd EPA-Connectivity-Monitor
git checkout v0.1.0   # or whichever tag you're verifying
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -buildid=" -o epa-connectivity-monitor.exe .
sha256sum epa-connectivity-monitor.exe
```

Match the hash in `SHA256SUMS.txt` from the same release tag → the published
binary was built from this exact source tree, with no hidden additions.

See [`SECURITY.md`](SECURITY.md) for the full trust statement (no telemetry,
what's logged, required permissions, data handling).

## Build (cross-compile from macOS / Linux)

```
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o epa-connectivity-monitor.exe .
```

## Run on Windows

```
epa-connectivity-monitor.exe --config config.yaml
epa-connectivity-monitor.exe --config config.yaml --snapshot  # one-shot PASS/FAIL summary table, no log file
epa-connectivity-monitor.exe --config config.yaml --once      # one-shot run, results still go to log file
epa-connectivity-monitor.exe --config config.yaml --dev       # dev mode: poll every 1s
epa-connectivity-monitor.exe --print-config                   # validate config
```

## Configuration

See `config.example.yaml`. Durations use Go syntax: `30s`, `1m`, `5m`, `1h`.

### Tagging checks

Every check accepts an optional `tags:` list — free-form `key:value` strings used
to group results in downstream analysis (no impact on check semantics).
Conventions used in the shipped configs:

- `region:{eu|nam|asia|aus|japan|global|local|internet|3rdparty}`
- `role:{signaling|signaling-tls|bootstrap|trust-renewal|pki-crl|pki-ocsp|ctl|update|auth|gateway|sanity|host-health|log-watch}`
- `cluster:{eur1|nam1|asia1|aus1|japan}` and `azure-region:<azureregion>` where applicable
- `provider:{azure-sb|msappproxy|digicert|microsoft|3rdparty}`

Tags appear as a `[k:v k:v ...]` suffix on the console line and as a `tags`
array on each JSON Lines record (omitted when empty, so older log consumers are
unaffected).

## Log format

JSON Lines, one record per check execution. Examples:

```json
{"timestamp":"2026-04-27T14:00:00Z","check":"default-gateway","type":"gateway_ping","target":"192.168.1.1","success":true,"latency_ms":1.42,"packet_loss_pct":0,"detail":"sent=3 recv=3 loss=0% avg=1.42ms"}
{"timestamp":"2026-04-27T14:00:00Z","check":"https-microsoft","type":"tcp443","target":"www.microsoft.com","success":true,"latency_ms":17.39,"detail":"connected www.microsoft.com:443 in 17.39ms"}
{"timestamp":"2026-04-27T14:00:00Z","check":"dns-microsoft-via-cloudflare","type":"dns_a","target":"microsoft.com","resolver":"1.1.1.1","success":true,"latency_ms":4.81,"detail":"A microsoft.com @1.1.1.1 -> 1 records [150.171.109.216] in 4.81ms"}
```

Common fields: `timestamp`, `check`, `type`, `target`, `success`, `latency_ms`,
`detail`, `error`. `dns_a` adds `resolver`; `gateway_ping` and `internet_ping`
add `packet_loss_pct`. Diagnostic check types (`tls`, `holdopen`, `host_health`,
`log_tail`) add structured detail under an `extra` object — for example:

```json
{"check":"tls-epa","type":"tls","target":"cwap-eur1-weur2.servicebus.windows.net","success":true,"latency_ms":47.10,"extra":{"tcp_connect_ms":31.64,"tls_handshake_ms":15.46,"tls_version":"TLS1.3","sni":"cwap-eur1-weur2.servicebus.windows.net"}}
{"check":"holdopen-epa","type":"holdopen","target":"cwap-eur1-weur2.servicebus.windows.net","success":false,"extra":{"held_seconds":62.4,"hold_target_sec":240,"closed_by":"peer_rst","classification":"peer_rst","tcp_keepalive":false}}
```

Logs rotate at `log_max_size_mb` (default 500 MB), keep `log_max_backups` files
(default 9), older than `log_max_age_days` (default 7) are deleted, and rotated
files are gzip-compressed. The logger also pauses writes if the log volume drops
below `log_min_free_disk_mb` (default 5120 MB / 5 GB) free, so the tool will not
fill the disk. Worst-case on-disk footprint with defaults: ~5 GB.

**Log location:** if `log_file` is omitted, the log is written as
`epa-connectivity-monitor.log` in the folder containing `epa-connectivity-monitor.exe`. Relative
paths are resolved against the executable's folder (not the current working
directory), so behaviour is identical when run interactively or as a Windows
service. Parent directories are created automatically.

## Run unattended (Windows service)

The binary has built-in Windows service support. From a cmd prompt **as Administrator**:

```cmd
:: Install + start (runs as LocalSystem, auto-starts at boot)
epa-connectivity-monitor.exe --install --config "C:\Tools\EPA Connectivity Monitor\config.yaml"

:: Stop / start / status (standard sc.exe commands)
sc stop  EpaConnectivityMonitor
sc start EpaConnectivityMonitor
sc query EpaConnectivityMonitor

:: Stop and remove cleanly
epa-connectivity-monitor.exe --uninstall
```

Notes:
- The .exe and the config file must live in a folder readable by **LocalSystem**.
  Don't install from a OneDrive / user profile path — copy to e.g.
  `C:\Tools\EPA Connectivity Monitor\` first.
- Service start/stop events are written to the Windows **Event Log** (source
  `EpaConnectivityMonitor`).
- Per-check results continue to go to the JSON-Lines log file as configured.
