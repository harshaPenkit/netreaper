from pathlib import Path

import pytest

from netreaper.core.models import Severity
from netreaper.plugins.device_audit import audit_config

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def vulnerable_config() -> str:
    return (EXAMPLES / "sample-cisco-ios-vulnerable.cfg").read_text()


@pytest.fixture
def hardened_config() -> str:
    return (EXAMPLES / "sample-cisco-ios-hardened.cfg").read_text()


def test_vulnerable_config_finds_expected_ids(vulnerable_config):
    findings = audit_config(vulnerable_config)
    ids = {f.id for f in findings}

    # AAA, legacy enable password, missing secret, password encryption, ssh v2,
    # http server, RW SNMP, well-known community, logging, telnet vty,
    # line password, missing access-class
    assert {
        "NET-001", "NET-002", "NET-003", "NET-004", "NET-005", "NET-006",
        "NET-007", "NET-008", "NET-009", "NET-010", "NET-012", "NET-013",
    }.issubset(ids)


def test_rw_snmp_is_critical_or_high(vulnerable_config):
    rw = [f for f in audit_config(vulnerable_config) if f.id == "NET-007"]
    assert len(rw) == 1
    assert rw[0].severity == Severity.HIGH
    assert rw[0].cvss >= 8.0


def test_telnet_finding_contains_line_evidence(vulnerable_config):
    telnet = [f for f in audit_config(vulnerable_config) if f.id == "NET-010"]
    assert telnet and "line vty 0 4" in telnet[0].evidence


def test_every_finding_has_remediation(vulnerable_config):
    for finding in audit_config(vulnerable_config):
        assert finding.remediation.strip()
        assert finding.description.strip()
        assert finding.evidence.strip()
        assert 0.0 <= finding.cvss <= 10.0


def test_hardened_config_has_no_findings(hardened_config):
    assert audit_config(hardened_config) == []


def test_empty_config_returns_aaa_finding_only_safely():
    findings = audit_config("!\nhostname empty\n!\n")
    assert any(f.id == "NET-001" for f in findings)
