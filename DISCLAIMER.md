# Disclaimer

**EPA Connectivity Monitor is a personal community diagnostic tool — not a Microsoft product.**

This software is built and maintained by Zaher Butt for the purpose of investigating
network behaviour observed by Entra Private Access (EPA) connector hosts. It is
**not affiliated with, endorsed by, or supported by Microsoft**. Use of this tool
does not create any Microsoft support obligation.

## What that means in practice

- **No warranty.** Provided as-is, without warranty of any kind, express or implied.
  The author and Microsoft accept no liability for any direct, indirect, incidental,
  consequential or other damages arising from its use.
- **No support.** There is no support contract, SLA, or guaranteed response time.
  Issues and questions are best-effort only via the public GitHub repository.
- **No telemetry.** The tool writes logs only to the local filesystem of the host
  it runs on. It does not transmit data anywhere. See [`SECURITY.md`](SECURITY.md)
  for what the tool does and does not do.
- **Output is observational, not authoritative.** The tool reports what *it* sees
  from the network vantage of the host it runs on. Interpretation of those
  observations — and any decision or action based on them — is the user's
  responsibility.
- **Logs are yours.** Collected logs remain on the customer environment unless the
  customer chooses to share them. Sharing logs with the author or any third party
  is at the customer's discretion.

## What this tool is good for

Building **independent network evidence** about what a connector host actually sees
when it talks to Microsoft endpoints, so that "is it Microsoft, the customer
network, or the connector?" conversations can be settled with data instead of
speculation.

## What it is not

- A replacement for **Microsoft Support** for any Entra Private Access issue.
  For official support, open a case at <https://admin.microsoft.com/> or via your
  organisation's standard Microsoft support channel.
- A connector troubleshooter. It does not interact with the EPA connector
  process, its configuration, or its credentials. It only observes the network.
- A monitoring product. It is a diagnostic helper for time-bounded
  investigations, not a managed/SLA-bound monitoring solution.

## License & attribution

See [`LICENSE`](LICENSE). When sharing output from this tool (charts, log
extracts, screenshots), please retain attribution to the source repository so
the framing above travels with the artefact.
