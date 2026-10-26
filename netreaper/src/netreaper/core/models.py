"""Core data models shared by every NetReaper plugin."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class Finding:
    """A single audit finding / weakness discovered by a plugin."""

    id: str
    title: str
    severity: Severity
    cvss: float
    description: str
    evidence: str
    remediation: str
    mitre_attack: str = ""
    cwe: str = ""

    def to_dict(self) -> dict:
        data = field_dict = dict(self.__dict__)
        data["severity"] = self.severity.value
        return data


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Highest severity first, then stable id ordering."""
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.id))
