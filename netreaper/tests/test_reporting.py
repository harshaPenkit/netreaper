import json

from netreaper.core.models import Finding, Severity
from netreaper.reporting.report import to_html, to_json, to_markdown


def _sample_findings():
    return [
        Finding(
            id="NET-007",
            title="Read-write SNMP community configured",
            severity=Severity.HIGH,
            cvss=8.1,
            description="RW community allows full reconfiguration.",
            evidence="snmp-server community private RW",
            remediation="Migrate to SNMPv3 authPriv.",
            mitre_attack="T1087",
            cwe="CWE-732",
        ),
        Finding(
            id="NET-004",
            title="Password encryption service disabled",
            severity=Severity.LOW,
            cvss=3.7,
            description="Plaintext passwords in config.",
            evidence="service password-encryption (directive absent)",
            remediation="Enable service password-encryption.",
        ),
    ]


def test_markdown_contains_summary_and_findings():
    md = to_markdown(_sample_findings(), title="Engagement X Report")
    assert "# Engagement X Report" in md
    assert "NET-007" in md
    assert "snmp-server community private RW" in md
    # High severity must be listed before Low
    assert md.index("NET-007") < md.index("NET-004")


def test_html_is_self_contained_and_escaped():
    html_doc = to_html(_sample_findings())
    assert html_doc.lstrip().startswith("<!DOCTYPE html>")
    assert "<style>" in html_doc
    assert "Read-write SNMP community" in html_doc


def test_json_round_trips():
    data = json.loads(to_json(_sample_findings()))
    assert len(data) == 2
    assert data[0]["severity"] == "High"
    assert data[0]["id"] == "NET-007"
