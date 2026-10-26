"""SNMP enumeration and weak-configuration auditor.

Requires the optional dependency group::

    pip install netreaper[snmp]

Only run against hosts you are explicitly authorized to test.
"""
from __future__ import annotations

from dataclasses import dataclass

DEFAULT_COMMUNITIES = ["public", "private", "cisco", "snmp", "admin", "monitor"]

# Standard MIB-II OIDs useful on internal engagements
OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
}


@dataclass
class SnmpResult:
    host: str
    community: str
    data: dict[str, str]


def _import_hlapi():
    try:
        from pysnmp.hlapi import (  # type: ignore
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            getCmd,
        )
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "SNMP support requires pysnmp. Install it with: pip install netreaper[snmp]"
        ) from exc
    return (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
    )


def get_system_info(
    host: str,
    community: str,
    port: int = 161,
    timeout: float = 1.5,
) -> SnmpResult | None:
    """Query MIB-II system OIDs over SNMPv2c. Returns None on auth failure."""
    (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
    ) = _import_hlapi()

    engine = SnmpEngine()
    transport = UdpTransportTarget((host, port), timeout=timeout, retries=0)
    variables = [ObjectType(ObjectIdentity(oid)) for oid in OIDS]

    error_indication, error_status, _, var_binds = next(
        getCmd(engine, CommunityData(community, mpModel=1), transport, ContextData(), *variables)
    )
    engine.closeDispatcher()

    if error_indication or error_status:
        return None

    data: dict[str, str] = {}
    for var_bind in var_binds:
        oid, value = var_bind[0].prettyPrint(), var_bind[1].prettyPrint()
        label = OIDS.get(oid, oid)
        data[label] = value
    return SnmpResult(host=host, community=community, data=data)


def audit_host(host: str, communities: list[str] | None = None) -> list[SnmpResult]:
    """Try a list of community strings against a host and return every success."""
    results: list[SnmpResult] = []
    for community in communities or DEFAULT_COMMUNITIES:
        result = get_system_info(host, community)
        if result is not None:
            results.append(result)
    return results
