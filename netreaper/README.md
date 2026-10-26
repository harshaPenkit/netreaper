# NetReaper

[![CI](https://github.com/YOUR-GITHUB-USERNAME/netreaper/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-GITHUB-USERNAME/netreaper/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

> Modular network attack and device-configuration audit framework for internal
> penetration tests. Built by a network engineer for engagements where the
> weakness lives in the infrastructure, not just the endpoints.

**Legal notice:** NetReaper is for authorized security testing and lab use only.
Running it against systems you do not own or lack written permission to test is
illegal. You are responsible for complying with all applicable laws.

## Why this tool exists

Internal pentest tooling is heavily host/AD-focused; the network layer is usually
audited by hand. NetReaper packages repeatable network checks — SNMP
enumeration, Layer-2 attack PoCs, and offline device-configuration auditing —
behind one tested, CI-backed CLI with consultant-ready report output.

## Features

| Module | Capability | Dependencies |
|---|---|---|---|
| `device_audit` | Offline Cisco IOS/IOS-XE config review: AAA, secrets, SNMP, SSH, HTTP, VTY hardening (13 rule IDs, CVSS + remediation) | none (stdlib) |
| `snmp_audit` | SNMPv2c community testing and MIB-II system enumeration | `pip install netreaper[snmp]` |
| `l2_attacks` | 802.1Q double-tagging (VLAN hopping) frame builder, ARP cache poisoning PoC | `pip install netreaper[l2]` |
| `reporting` | Markdown / self-contained HTML / JSON reports with severity summary | none (stdlib) |

## Install

```bash
git clone https://github.com/YOUR-GITHUB-USERNAME/netreaper.git
cd netreaper
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

Audit a device configuration and emit all three report formats:

```bash
netreaper audit examples/sample-cisco-ios-vulnerable.cfg \
  --md out/report.md --html out/report.html --json out/findings.json
```

Example output:

```
NetReaper v0.1.0 — 12 finding(s)

ID       SEVERITY  CVSS  TITLE
------------------------------------------------------------------------------
NET-007  High      8.1   Read-write SNMP community configured
NET-010  High      7.4   Telnet permitted on VTY lines
NET-002  High      7.2   Legacy enable password configured
...
```

SNMP enumeration (authorized lab target):

```python
from netreaper.plugins.snmp_audit import audit_host
for result in audit_host("10.10.10.1"):
    print(result.community, result.data)
```

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
pytest --cov=netreaper
```

## Roadmap

- [ ] Juniper Junos and Arista EOS config parsers
- [ ] SNMPv3 auth (USM) auditing and interface/VLAN extraction
- [ ] LLMNR/NBT-NS poisoner module (Scapy)
- [ ] DTP switch-spoofing check
- [ ] CSV/Excel export for client deliverables

## License

MIT — see [LICENSE](LICENSE).
