#!/usr/bin/env python3
"""
aggregate_results.py — SecurePipeline scan output aggregator

Reads JSON output files from individual security scanners (Semgrep, Trivy,
OWASP Dependency Check, OWASP ZAP), normalises findings into a unified schema,
and writes a security-summary.json file. Exits with code 1 if any CRITICAL or
HIGH severity findings exist.

Usage:
    python scripts/aggregate_results.py [--results-dir scan-results] [--output security-summary.json]
"""

import argparse
import json
import os
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Unified finding schema:
#   { scanner, finding_id, severity, file, line, description, cve }
# ---------------------------------------------------------------------------

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}


def normalise_severity(raw: str) -> str:
    upper = raw.upper()
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "LOW": "LOW",
        "INFORMATIONAL": "INFO",
        "INFO": "INFO",
        "UNKNOWN": "UNKNOWN",
    }
    return mapping.get(upper, "UNKNOWN")


# ---------------------------------------------------------------------------
# Parser: Semgrep JSON
# ---------------------------------------------------------------------------

def parse_semgrep(data: dict) -> list[dict]:
    findings = []
    for result in data.get("results", []):
        findings.append(
            {
                "scanner": "semgrep",
                "finding_id": result.get("check_id", "unknown"),
                "severity": normalise_severity(result.get("extra", {}).get("severity", "UNKNOWN")),
                "file": result.get("path", ""),
                "line": result.get("start", {}).get("line", 0),
                "description": result.get("extra", {}).get("message", ""),
                "cve": None,
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Parser: Trivy JSON (image + config)
# ---------------------------------------------------------------------------

def parse_trivy(data: dict) -> list[dict]:
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "")
        # Vulnerability results
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "scanner": "trivy",
                    "finding_id": vuln.get("VulnerabilityID", "unknown"),
                    "severity": normalise_severity(vuln.get("Severity", "UNKNOWN")),
                    "file": target,
                    "line": 0,
                    "description": vuln.get("Description", vuln.get("Title", "")),
                    "cve": vuln.get("VulnerabilityID"),
                }
            )
        # Misconfiguration results
        for misconfig in result.get("Misconfigurations", []) or []:
            findings.append(
                {
                    "scanner": "trivy-config",
                    "finding_id": misconfig.get("ID", "unknown"),
                    "severity": normalise_severity(misconfig.get("Severity", "UNKNOWN")),
                    "file": target,
                    "line": 0,
                    "description": misconfig.get("Description", ""),
                    "cve": None,
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Parser: OWASP Dependency Check JSON
# ---------------------------------------------------------------------------

def parse_depcheck(data: dict) -> list[dict]:
    findings = []
    dependencies = data.get("dependencies", [])
    for dep in dependencies:
        for vuln in dep.get("vulnerabilities", []) or []:
            severity_raw = vuln.get("severity", "UNKNOWN")
            findings.append(
                {
                    "scanner": "dependency-check",
                    "finding_id": vuln.get("name", "unknown"),
                    "severity": normalise_severity(severity_raw),
                    "file": dep.get("fileName", ""),
                    "line": 0,
                    "description": vuln.get("description", ""),
                    "cve": vuln.get("name") if vuln.get("name", "").startswith("CVE-") else None,
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Parser: OWASP ZAP JSON
# ---------------------------------------------------------------------------

def parse_zap(data: dict) -> list[dict]:
    findings = []
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            risk = alert.get("riskdesc", "").split(" ")[0]
            findings.append(
                {
                    "scanner": "zap",
                    "finding_id": alert.get("pluginid", "unknown"),
                    "severity": normalise_severity(risk),
                    "file": alert.get("url", ""),
                    "line": 0,
                    "description": alert.get("desc", alert.get("name", "")),
                    "cve": None,
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Parser: Gitleaks JSON
# ---------------------------------------------------------------------------

def parse_gitleaks(data: list) -> list[dict]:
    findings = []
    for leak in data or []:
        findings.append(
            {
                "scanner": "gitleaks",
                "finding_id": leak.get("RuleID", "unknown"),
                "severity": "HIGH",
                "file": leak.get("File", ""),
                "line": leak.get("StartLine", 0),
                "description": f"Secret detected: {leak.get('Description', '')} — Match: {leak.get('Match', '')[:40]}",
                "cve": None,
            }
        )
    return findings


# ---------------------------------------------------------------------------
# File loader — returns (parser_fn, data) or None if file missing / parse error
# ---------------------------------------------------------------------------

SCANNER_FILES = {
    "semgrep.json": parse_semgrep,
    "trivy-report.json": parse_trivy,
    "trivy-config.json": parse_trivy,
    "dependency-check-report.json": parse_depcheck,
    "zap-report.json": parse_zap,
    "gitleaks-report.json": parse_gitleaks,
}


def load_and_parse(results_dir: str) -> tuple[list[dict], dict[str, Any]]:
    all_findings: list[dict] = []
    scanner_stats: dict[str, Any] = {}

    for filename, parser in SCANNER_FILES.items():
        path = os.path.join(results_dir, filename)
        scanner_name = filename.replace(".json", "").replace("-report", "")

        if not os.path.exists(path):
            scanner_stats[scanner_name] = {"status": "not_run", "findings": 0}
            continue

        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[WARN] Could not parse {path}: {exc}", file=sys.stderr)
            scanner_stats[scanner_name] = {"status": "parse_error", "findings": 0}
            continue

        findings = parser(raw)
        all_findings.extend(findings)
        scanner_stats[scanner_name] = {
            "status": "ok",
            "findings": len(findings),
            "by_severity": count_by_severity(findings),
        }
        print(f"[INFO] {scanner_name}: {len(findings)} finding(s) parsed from {filename}")

    return all_findings, scanner_stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def count_by_severity(findings: list[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def print_ascii_table(findings: list[dict]) -> None:
    if not findings:
        print("\n  No findings across all scanners.\n")
        return

    col_widths = {"scanner": 20, "severity": 10, "file": 35, "description": 50}
    header = (
        f"{'Scanner':<{col_widths['scanner']}} "
        f"{'Severity':<{col_widths['severity']}} "
        f"{'File':<{col_widths['file']}} "
        f"{'Description':<{col_widths['description']}}"
    )
    sep = "-" * len(header)

    print(f"\n{'=' * len(header)}")
    print("  SECURITY FINDINGS SUMMARY")
    print(f"{'=' * len(header)}")
    print(header)
    print(sep)

    sorted_findings = sorted(findings, key=lambda x: SEVERITY_RANK.get(x["severity"], 0), reverse=True)

    for f in sorted_findings:
        scanner = f["scanner"][:col_widths["scanner"]]
        sev = f["severity"][:col_widths["severity"]]
        file_ = (f["file"] or "")[-col_widths["file"]:]
        desc = (f["description"] or "")[:col_widths["description"]]
        print(
            f"{scanner:<{col_widths['scanner']}} "
            f"{sev:<{col_widths['severity']}} "
            f"{file_:<{col_widths['file']}} "
            f"{desc:<{col_widths['description']}}"
        )

    print(sep)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate DevSecOps scan results")
    parser.add_argument("--results-dir", default="scan-results", help="Directory containing scanner JSON output files")
    parser.add_argument("--output", default="security-summary.json", help="Output path for the unified summary JSON")
    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"[WARN] Results directory '{args.results_dir}' does not exist — no scan files to aggregate.")
        summary = {
            "passed": True,
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "scanners": {},
            "findings": [],
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        print(f"[INFO] Wrote empty summary to {args.output}")
        return 0

    all_findings, scanner_stats = load_and_parse(args.results_dir)

    counts = count_by_severity(all_findings)
    has_critical_or_high = (counts["CRITICAL"] > 0 or counts["HIGH"] > 0)
    passed = not has_critical_or_high

    summary = {
        "passed": passed,
        "total_findings": len(all_findings),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "info": counts["INFO"],
        "scanners": scanner_stats,
        "findings": all_findings,
    }

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print_ascii_table(all_findings)

    print(f"Total findings : {len(all_findings)}")
    print(f"  CRITICAL     : {counts['CRITICAL']}")
    print(f"  HIGH         : {counts['HIGH']}")
    print(f"  MEDIUM       : {counts['MEDIUM']}")
    print(f"  LOW          : {counts['LOW']}")
    print(f"  INFO         : {counts['INFO']}")
    print()
    print(f"Pipeline gate  : {'PASS' if passed else 'FAIL (CRITICAL/HIGH found)'}")
    print(f"Summary written: {args.output}")

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
