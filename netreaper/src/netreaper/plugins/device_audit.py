"""Cisco IOS / IOS-XE device configuration auditor.

Parses a running or startup configuration (plain text, e.g. output of
``show running-config``) and returns :class:`Finding` objects for common
management-plane weaknesses.

Pure standard library, no device access required — ideal for offline
configuration review engagements and for unit testing.
"""
from __future__ import annotations

import re

from netreaper.core.models import Finding, Severity

WELL_KNOWN_COMMUNITIES = {"public", "private", "cisco", "snmp", "default"}


def _finding(
    fid: str,
    title: str,
    severity: Severity,
    cvss: float,
    description: str,
    evidence: str,
    remediation: str,
    mitre_attack: str = "",
    cwe: str = "",
) -> Finding:
    return Finding(
        id=fid,
        title=title,
        severity=severity,
        cvss=cvss,
        description=description,
        evidence=evidence.strip(),
        remediation=remediation,
        mitre_attack=mitre_attack,
        cwe=cwe,
    )


def _indented_blocks(raw_lines: list[str], header_regex: str) -> list[list[str]]:
    """Collect config sections (e.g. ``line vty 0 4``) with their indented body."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for raw in raw_lines:
        header = re.match(header_regex, raw.strip())
        if header:
            if current is not None:
                blocks.append(current)
            current = [raw.strip()]
        elif current is not None:
            if raw.startswith((" ", "\t")) and raw.strip():
                current.append(raw.strip())
            else:
                blocks.append(current)
                current = None
    if current is not None:
        blocks.append(current)
    return blocks


def audit_config(config_text: str) -> list[Finding]:
    """Audit a Cisco IOS/IOS-XE configuration string and return findings."""
    findings: list[Finding] = []
    raw_lines = config_text.splitlines()
    lines = [line.strip() for line in raw_lines]
    full_text = "\n".join(lines)

    # NET-001: AAA framework not enabled
    if not any(line.startswith("aaa new-model") for line in lines):
        findings.append(
            _finding(
                "NET-001",
                "AAA not enabled",
                Severity.HIGH,
                7.5,
                "The device is not using the AAA framework, so authentication and "
                "authorization fall back to weak local line passwords.",
                "aaa new-model (directive absent)",
                "Enable AAA and centralize access: 'aaa new-model', then configure "
                "TACACS+ or RADIUS servers and explicit login/exec authorization.",
                "T1078",
                "CWE-306",
            )
        )

    # NET-002: legacy 'enable password' (weak/reversible Type 7 or plaintext)
    for line in lines:
        if line.startswith("enable password"):
            findings.append(
                _finding(
                    "NET-002",
                    "Legacy enable password configured",
                    Severity.HIGH,
                    7.2,
                    "'enable password' uses the reversible Type 7 cipher (or plaintext) "
                    "and is trivially recoverable from the configuration.",
                    line,
                    "Remove 'enable password' and use 'enable secret' (Type 8/9 "
                    "PBKDF2/scrypt hashing) instead.",
                    "T1552.001",
                    "CWE-522",
                )
            )

    # NET-003: no enable secret
    if not any(line.startswith("enable secret") for line in lines):
        findings.append(
            _finding(
                "NET-003",
                "No privileged-mode secret defined",
                Severity.MEDIUM,
                5.5,
                "There is no 'enable secret', so privileged EXEC mode may rely on the "
                "weak legacy enable password or no secret at all.",
                "enable secret (directive absent)",
                "Configure 'enable secret 9 <hash>' using a strong, unique passphrase.",
                "T1078",
                "CWE-521",
            )
        )

    # NET-004: service password-encryption missing
    if "service password-encryption" not in full_text:
        findings.append(
            _finding(
                "NET-004",
                "Password encryption service disabled",
                Severity.LOW,
                3.7,
                "Without 'service password-encryption', line and local passwords are "
                "stored in plaintext in the configuration file.",
                "service password-encryption (directive absent)",
                "Apply 'service password-encryption' and migrate secrets to Type 8/9 "
                "hashes (Type 7 only obfuscates, it does not protect).",
                "T1552.001",
                "CWE-312",
            )
        )

    # NET-005: SSH v2 not enforced
    if not any(re.match(r"ip ssh version\s+2", line) for line in lines):
        findings.append(
            _finding(
                "NET-005",
                "SSH version 2 not enforced",
                Severity.MEDIUM,
                5.9,
                "The device may negotiate legacy SSHv1, which has known cryptographic "
                "weaknesses and is exploitable for session manipulation.",
                "ip ssh version 2 (directive absent)",
                "Configure 'ip ssh version 2', disable SSHv1, and use 2048-bit+ RSA/"
                "ECDSA host keys with strong encryption algorithms.",
                "T1021.004",
                "CWE-327",
            )
        )

    # NET-006: unencrypted HTTP management plane
    if any(line == "ip http server" for line in lines):
        findings.append(
            _finding(
                "NET-006",
                "Plaintext HTTP management server enabled",
                Severity.MEDIUM,
                6.5,
                "The IOS HTTP server exposes management over unencrypted HTTP, allowing "
                "credential interception and session hijacking on the local segment.",
                "ip http server",
                "Run 'no ip http server'. If web management is required, use "
                "'ip http secure-server' restricted to a management VLAN with an ACL.",
                "T1040",
                "CWE-319",
            )
        )

    # NET-007 / NET-008: SNMP community weaknesses
    for line in lines:
        match = re.match(r"snmp-server community\s+(\S+)(?:\s+(\S+))?", line)
        if not match:
            continue
        community, access = match.group(1), (match.group(2) or "").lower()
        if access == "rw":
            findings.append(
                _finding(
                    "NET-007",
                    "Read-write SNMP community configured",
                    Severity.HIGH,
                    8.1,
                    "A read-write SNMP community allows full device reconfiguration, "
                    "including configuration replacement and access-list tampering.",
                    line,
                    "Remove RW communities. Restrict SNMP to a management VLAN via ACL "
                    "and migrate to SNMPv3 with authPriv and least-privilege views.",
                    "T1087",
                    "CWE-732",
                )
            )
        if community.lower() in WELL_KNOWN_COMMUNITIES:
            findings.append(
                _finding(
                    "NET-008",
                    "Default/well-known SNMP community string",
                    Severity.MEDIUM,
                    5.3,
                    f"Community string '{community}' is one of the first values tried "
                    "by automated scanners and worm tooling.",
                    line,
                    "Replace well-known community strings with high-entropy values, "
                    "bind them to an ACL, and migrate to SNMPv3 authPriv.",
                    "T1592",
                    "CWE-798",
                )
            )

    # NET-009: no centralized or buffered logging
    if not any(
        line.startswith("logging host") or line.startswith("logging buffered")
        for line in lines
    ):
        findings.append(
            _finding(
                "NET-009",
                "Logging not configured",
                Severity.LOW,
                3.3,
                "Without buffered or host-based logging, attacks and configuration "
                "changes leave no forensic trail.",
                "logging host / logging buffered (directives absent)",
                "Configure 'logging buffered' and ship logs to a central SIEM via "
                "'logging host <ip>', with reliable delivery and NTP-synced clocks.",
                "T1070",
                "CWE-778",
            )
        )

    # VTY (remote management line) checks
    for block in _indented_blocks(raw_lines, r"line vty"):
        header, body = block[0], "\n".join(block[1:])
        if re.search(r"transport input\s+[^\n]*\btelnet\b", body) or "transport input all" in body:
            findings.append(
                _finding(
                    "NET-010",
                    "Telnet permitted on VTY lines",
                    Severity.HIGH,
                    7.4,
                    f"VTY block '{header}' accepts Telnet, which transmits credentials "
                    "and session data in cleartext.",
                    f"{header}\n{body}",
                    f"Under '{header}' set 'transport input ssh' and remove Telnet.",
                    "T1040",
                    "CWE-319",
                )
            )
        elif "transport input ssh" not in body:
            findings.append(
                _finding(
                    "NET-011",
                    "VTY transport not restricted to SSH",
                    Severity.MEDIUM,
                    5.3,
                    f"VTY block '{header}' does not explicitly restrict transport to SSH, "
                    "leaving default/legacy protocols available.",
                    f"{header}\n{body}",
                    f"Under '{header}' explicitly set 'transport input ssh'.",
                    "T1021.004",
                    "CWE-749",
                )
            )
        if re.search(r"(^|\n)\s*password\s+", body):
            findings.append(
                _finding(
                    "NET-012",
                    "Weak line password on VTY",
                    Severity.MEDIUM,
                    6.1,
                    f"VTY block '{header}' uses a local line password instead of AAA "
                    "user-level authentication.",
                    f"{header}\n{body}",
                    "Remove line passwords and enforce 'login authentication' against "
                    "the AAA (TACACS+/RADIUS) policy.",
                    "T1078",
                    "CWE-306",
                )
            )
        if "access-class" not in body:
            findings.append(
                _finding(
                    "NET-013",
                    "VTY lines not restricted by ACL",
                    Severity.LOW,
                    3.9,
                    f"VTY block '{header}' has no 'access-class' restriction, so any "
                    "reachable network can attempt management logins.",
                    f"{header}\n{body}",
                    f"Apply 'access-class <acl> in' under '{header}' to limit management "
                    "access to trusted management subnets.",
                    "T1021.004",
                    "CWE-284",
                )
            )

    return findings
