"""Report generators: turn Finding lists into Markdown, HTML, or JSON."""
from __future__ import annotations

import html
from collections import Counter

from netreaper.core.models import Finding, Severity, findings_to_json, sort_findings

_CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;margin:2rem auto;max-width:980px;color:#1f2937}
h1{border-bottom:3px solid #b91c1c;padding-bottom:.4rem}
h2{margin-top:2rem;border-left:5px solid #b91c1c;padding-left:.6rem}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #d1d5db;padding:.5rem .7rem;text-align:left;font-size:.92rem}
th{background:#f3f4f6}
.sev-Critical{color:#fff;background:#7f1d1d;padding:.15rem .5rem;border-radius:4px}
.sev-High{color:#fff;background:#b91c1c;padding:.15rem .5rem;border-radius:4px}
.sev-Medium{color:#fff;background:#c2410c;padding:.15rem .5rem;border-radius:4px}
.sev-Low{color:#fff;background:#a16207;padding:.15rem .5rem;border-radius:4px}
.sev-Info{color:#fff;background:#374151;padding:.15rem .5rem;border-radius:4px}
code{background:#f3f4f6;padding:.1rem .3rem;border-radius:3px}
.evidence{background:#f9fafb;border:1px solid #e5e7eb;padding:.6rem;white-space:pre-wrap}
"""


def _summary(findings: list[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


def to_json(findings: list[Finding]) -> str:
    return findings_to_json(sort_findings(findings))


def to_markdown(findings: list[Finding], title: str = "NetReaper Audit Report") -> str:
    findings = sort_findings(findings)
    counts = _summary(findings)
    out = [f"# {title}", ""]
    out.append("## Executive Summary")
    out.append("")
    out.append(f"Total findings: **{len(findings)}**")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|----------|-------|")
    for sev in Severity:
        out.append(f"| {sev.value} | {counts.get(sev, 0)} |")
    out.append("")
    out.append("## Findings")
    out.append("")
    for f in findings:
        out.append(f"### {f.id} — {f.title}")
        out.append("")
        out.append(f"- **Severity:** {f.severity.value} (CVSS v3.1: {f.cvss})")
        if f.mitre_attack:
            out.append(f"- **MITRE ATT&CK:** {f.mitre_attack}")
        if f.cwe:
            out.append(f"- **CWE:** {f.cwe}")
        out.append(f"- **Description:** {f.description}")
        out.append("- **Evidence:**")
        out.append("")
        out.append("```")
        out.append(f.evidence)
        out.append("```")
        out.append("")
        out.append(f"- **Remediation:** {f.remediation}")
        out.append("")
    return "\n".join(out)


def to_html(findings: list[Finding], title: str = "NetReaper Audit Report") -> str:
    findings = sort_findings(findings)
    counts = _summary(findings)
    parts = [
        "<!DOCTYPE html>",
        "<html lang='en'><head><meta charset='utf-8'>",
        f"<title>{html.escape(title)}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>{html.escape(title)}</h1>",
        "<h2>Executive Summary</h2>",
        f"<p>Total findings: <strong>{len(findings)}</strong></p>",
        "<table><tr><th>Severity</th><th>Count</th></tr>",
    ]
    for sev in Severity:
        parts.append(
            f"<tr><td><span class='sev-{sev.value}'>{sev.value}</span></td>"
            f"<td>{counts.get(sev, 0)}</td></tr>"
        )
    parts.append("</table><h2>Findings</h2>")
    for f in findings:
        parts.append(f"<h3>{html.escape(f.id)} — {html.escape(f.title)}</h3>")
        parts.append(
            f"<p><span class='sev-{f.severity.value}'>{f.severity.value}</span> "
            f"CVSS {f.cvss} | MITRE {html.escape(f.mitre_attack or 'N/A')} | "
            f"CWE {html.escape(f.cwe or 'N/A')}</p>"
        )
        parts.append(f"<p>{html.escape(f.description)}</p>")
        parts.append("<div class='evidence'><strong>Evidence:</strong><br>")
        parts.append(html.escape(f.evidence))
        parts.append("</div>")
        parts.append(f"<p><strong>Remediation:</strong> {html.escape(f.remediation)}</p>")
    parts.append("</body></html>")
    return "\n".join(parts)
