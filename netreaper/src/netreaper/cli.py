"""NetReaper command-line interface."""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from netreaper import __version__
from netreaper.core.models import Severity, sort_findings
from netreaper.plugins.device_audit import audit_config
from netreaper.reporting.report import to_html, to_json, to_markdown


def _print_summary(findings) -> None:
    findings = sort_findings(findings)
    counts = Counter(f.severity for f in findings)
    print(f"\nNetReaper v{__version__} — {len(findings)} finding(s)\n")
    print(f"{'ID':<9}{'SEVERITY':<10}{'CVSS':<6}TITLE")
    print("-" * 78)
    for f in findings:
        print(f"{f.id:<9}{f.severity.value:<10}{f.cvss:<6}{f.title}")
    print("-" * 78)
    print(" ".join(f"{sev.value}: {counts.get(sev, 0)}" for sev in Severity) + "\n")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netreaper",
        description="Network attack & device configuration audit framework.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Audit a network device configuration file")
    audit.add_argument("config", type=Path, help="Path to a device config (e.g. show run output)")
    audit.add_argument("--json", dest="json_out", type=Path, help="Write JSON findings to file")
    audit.add_argument("--md", dest="md_out", type=Path, help="Write Markdown report to file")
    audit.add_argument("--html", dest="html_out", type=Path, help="Write HTML report to file")

    sub.add_parser("version", help="Print version and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"netreaper {__version__}")
        return 0

    if args.command == "audit":
        if not args.config.is_file():
            print(f"error: config file not found: {args.config}", file=sys.stderr)
            return 2
        findings = audit_config(args.config.read_text(encoding="utf-8", errors="replace"))
        _print_summary(findings)
        if args.json_out:
            args.json_out.write_text(to_json(findings), encoding="utf-8")
            print(f"[+] JSON report written: {args.json_out}")
        if args.md_out:
            args.md_out.write_text(to_markdown(findings), encoding="utf-8")
            print(f"[+] Markdown report written: {args.md_out}")
        if args.html_out:
            args.html_out.write_text(to_html(findings), encoding="utf-8")
            print(f"[+] HTML report written: {args.html_out}")
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2
